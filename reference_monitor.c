
#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include "lib/include/scth.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea De Filippis");
MODULE_DESCRIPTION("reference monitor service");

#define MODNAME "REFERENCE_MONITOR"
#define AUDIT if (1)
#define NO (0)
#define YES (NO + 1)

// -------------------------- MODULE PARAMETERS --------------------------

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);
MODULE_PARM_DESC(the_syscall_table, "Retrieved syscall table address through the_usctm module");

// -------------------------- MODULE VARIABLES --------------------------

unsigned long new_sys_call_array[] = {0x0}; // It will set to the syscalls at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

unsigned long the_ni_syscall;

// -------------------------- MODULE SYSCALLS --------------------------

// sem_ds: semaphore "descriptor" returned by create semaphore syscall
// tokens: number of token to take
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _sem_lock, int, sem_ds, int, tokens)
{
#else
asmlinkage long sys_sem_lock(int tokens)
{
#endif

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_sem_lock = (unsigned long)__x64_sys_sem_lock;
#endif

/**
 * @brief
 *
 * @return int
 */
int init_module(void)
{

    int i;
    int ret;

    if (the_syscall_table == 0x0)
    {
        printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
        return -1;
    }

    AUDIT
    {
        printk("%s: queuing example received sys_call_table address %px\n", MODNAME, (void *)the_syscall_table);
        printk("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
    }

    new_sys_call_array[0] = (unsigned long)sys_sem_lock;

    ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)the_syscall_table, &the_ni_syscall);

    if (ret != HACKED_ENTRIES)
    {
        printk("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
        return -1;
    }

    unprotect_memory();

    for (i = 0; i < HACKED_ENTRIES; i++)
    {
        ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
    }

    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);

    return 0;
}

void cleanup_module(void)
{

    int i;

    printk("%s: shutting down\n", MODNAME);

    unprotect_memory();
    for (i = 0; i < HACKED_ENTRIES; i++)
    {
        ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
    }
    protect_memory();
    printk("%s: sys-call table restored to its original content\n", MODNAME);
}