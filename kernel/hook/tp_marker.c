#include "hook/tp_marker.h"

#include "linux/cred.h"
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>

#include "policy/allowlist.h"
#include "klog.h"
#include "selinux/selinux.h"

#ifdef CONFIG_KSU_NON_ANDROID
#include <trace/events/sched.h>
static bool enable_tracepoints = true;
static int init_pid_global = 0;
#endif

// Tracepoint registration count management
// == 1: just us
// >  1: someone else is also using syscall tracepoint e.g. ftrace
static int tracepoint_reg_count = 0;
static DEFINE_SPINLOCK(tracepoint_reg_lock);

int ksu_tp_marker_reg_count(void)
{
    return tracepoint_reg_count;
}

void ksu_tp_marker_lock(unsigned long *flags)
{
    spin_lock_irqsave(&tracepoint_reg_lock, *flags);
}

void ksu_tp_marker_unlock(unsigned long *flags)
{
    spin_unlock_irqrestore(&tracepoint_reg_lock, *flags);
}

void ksu_tp_marker_inc_reg_count(void)
{
    tracepoint_reg_count++;
}

void ksu_tp_marker_dec_reg_count(void)
{
    tracepoint_reg_count--;
}

void ksu_clear_task_tracepoint_flag_if_needed(struct task_struct *t)
{
    unsigned long flags;
    spin_lock_irqsave(&tracepoint_reg_lock, flags);
    if (tracepoint_reg_count <= 1) {
        ksu_clear_task_tracepoint_flag(t);
    }
    spin_unlock_irqrestore(&tracepoint_reg_lock, flags);
}

// Process marking management
static void handle_process_mark(bool mark)
{
    struct task_struct *p, *t;
    read_lock(&tasklist_lock);
    for_each_process_thread (p, t) {
        if (mark)
            ksu_set_task_tracepoint_flag(t);
        else
            ksu_clear_task_tracepoint_flag(t);
    }
    read_unlock(&tasklist_lock);
}

void ksu_mark_all_process(void)
{
#ifndef CONFIG_KSU_NON_ANDROID
    handle_process_mark(true);
    pr_info("tp_marker: mark all user process done!\n");
#endif
}

void ksu_unmark_all_process(void)
{
#ifndef CONFIG_KSU_NON_ANDROID
    handle_process_mark(false);
    pr_info("tp_marker: unmark all user process done!\n");
#endif
}

void ksu_mark_running_process_locked(void)
{
#ifdef CONFIG_KSU_NON_ANDROID
    // For non-Android: just mark the host init (pid 1) if it matches
    // Individual processes get marked when Android container starts
    pr_info("tp_marker: non-android mode, skipping process marking\n");
#else
    struct task_struct *p, *t;
    read_lock(&tasklist_lock);
    for_each_process_thread (p, t) {
        if (task_pid_vnr(t) != 1 && !t->mm) {
            // skip kernel threads, but always allow pid 1
            continue;
        }
        int uid = task_uid(t).val;
        const struct cred *cred = get_task_cred(t);
        bool ksu_root_process = uid == 0 && is_task_ksu_domain(cred);
        bool is_zygote_process = is_zygote(cred);
        bool is_shell = uid == 2000;
        // before boot completed, we shall mark init for marking zygote
        bool is_init = task_pid_vnr(t) == 1;
        if (ksu_root_process || is_zygote_process || is_shell || is_init ||
            ksu_is_allow_uid(uid)) {
            ksu_set_task_tracepoint_flag(t);
            pr_info("tp_marker: mark process: pid:%d, uid: %d, comm:%s\n",
                    t->pid, uid, t->comm);
        } else {
            ksu_clear_task_tracepoint_flag(t);
            pr_info("tp_marker: unmark process: pid:%d, uid: %d, comm:%s\n",
                    t->pid, uid, t->comm);
        }
        put_cred(cred);
    }
    read_unlock(&tasklist_lock);
#endif
}

void ksu_mark_running_process(void)
{
    unsigned long flags;
    spin_lock_irqsave(&tracepoint_reg_lock, flags);
    if (tracepoint_reg_count <= 1) {
        ksu_mark_running_process_locked();
    } else {
        pr_info(
            "tp_marker: not mark running process since syscall tracepoint is in use\n");
    }
    spin_unlock_irqrestore(&tracepoint_reg_lock, flags);
}

// Get task mark status
// Returns: 1 if marked, 0 if not marked, -ESRCH if task not found
int ksu_get_task_mark(pid_t pid)
{
    struct task_struct *task;
    int marked = -ESRCH;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        marked = test_task_syscall_work(task, SYSCALL_TRACEPOINT) ? 1 : 0;
#else
        marked = test_tsk_thread_flag(task, TIF_SYSCALL_TRACEPOINT) ? 1 : 0;
#endif
        put_task_struct(task);
    } else {
        rcu_read_unlock();
    }

    return marked;
}

// Set task mark status
// Returns: 0 on success, -ESRCH if task not found
int ksu_set_task_mark(pid_t pid, bool mark)
{
    struct task_struct *task;
    int ret = -ESRCH;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();
        if (mark) {
            ksu_set_task_tracepoint_flag(task);
            pr_info("tp_marker: marked task pid=%d comm=%s\n", pid, task->comm);
        } else {
            ksu_clear_task_tracepoint_flag(task);
            pr_info("tp_marker: unmarked task pid=%d comm=%s\n", pid,
                    task->comm);
        }
        put_task_struct(task);
        ret = 0;
    } else {
        rcu_read_unlock();
    }

    return ret;
}

#ifdef CONFIG_KSU_NON_ANDROID
// Called when a new process execs - track Android init container
static void ksu_exec_handler(void *data, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    if (unlikely(enable_tracepoints && task_pid_vnr(p) == 1 && strcmp(bprm->filename, "/system/bin/init") == 0)) {
        init_pid_global = p->pid;
        pr_info("tp_marker: Android init (PID %i) namespace started\n", init_pid_global);
        ksu_set_task_tracepoint_flag(p);
    }
}

// Called when a process exits - check if Android container died
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static void ksu_exit_handler(void *data, struct task_struct *p, bool group_dead)
#else
static void ksu_exit_handler(void *data, struct task_struct *p)
#endif
{
    if (unlikely(enable_tracepoints && p->pid == init_pid_global)) {
        enable_tracepoints = false;
        pr_info("tp_marker: Android init (PID %i) namespace died\n", init_pid_global);
    }
}

void ksu_tp_marker_sched_init(void)
{
    int ret;
    ret = register_trace_sched_process_exec(ksu_exec_handler, NULL);
    if (ret) {
        pr_err("tp_marker: failed to register sched_process_exec tracepoint: %d\n", ret);
    } else {
        pr_info("tp_marker: sched_process_exec tracepoint registered\n");
    }

    ret = register_trace_sched_process_exit(ksu_exit_handler, NULL);
    if (ret) {
        pr_err("tp_marker: failed to register sched_process_exit tracepoint: %d\n", ret);
    } else {
        pr_info("tp_marker: sched_process_exit tracepoint registered\n");
    }
}

void ksu_tp_marker_sched_exit(void)
{
    unregister_trace_sched_process_exec(ksu_exec_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("tp_marker: sched_process_exec tracepoint unregistered\n");

    unregister_trace_sched_process_exit(ksu_exit_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("tp_marker: sched_process_exit tracepoint unregistered\n");
}
#endif
