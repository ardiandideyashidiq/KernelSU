#ifndef __KSU_H_KSUD_BOOT
#define __KSU_H_KSUD_BOOT

#include <linux/types.h>

void on_post_fs_data(void);
void on_module_mounted(void);
void on_boot_completed(void);

#ifdef CONFIG_KSU_HANDLE_INPUT_EVENT
bool ksu_is_safe_mode(void);
#endif

#ifdef CONFIG_KSU_SELINUX
extern u32 ksu_file_sid;
#endif

extern bool ksu_module_mounted;
extern bool ksu_boot_completed;

#endif // __KSU_H_KSUD_BOOT
