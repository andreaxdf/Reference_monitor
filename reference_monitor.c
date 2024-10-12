
#define EXPORT_SYMTAB
#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <trace/syscall.h>

#include "lib/include/scth.h"
#include "utils/include/constants.h"
#include "utils/include/probes.h"
#include "utils/include/reference_monitor_state.h"
#include "utils/include/sha256_utils.h"
#include "utils/include/state.h"
#include "utils/include/utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea De Filippis");
MODULE_DESCRIPTION("reference monitor service");

// -------------------------- MODULE PARAMETERS --------------------------

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);
MODULE_PARM_DESC(the_syscall_table,
                 "Retrieved syscall table address through the_usctm module");

unsigned char the_password[MAX_PASSWD_LENGHT];
unsigned char hashed_password[SHA256_DIGEST_SIZE];
module_param_string(the_password, the_password, MAX_PASSWD_LENGHT,
                    0);  // This parameter cannot be accessed via vfs
MODULE_PARM_DESC(the_password,
                 "Password required to use the reference monitor");

// -------------------------- MODULE STRUCTURES -------------------------

enum mode {
    ADD,
    REMOVE,
};

// -------------------------- MODULE VARIABLES --------------------------

unsigned long new_sys_call_array[] = {
    0x0, 0x0, 0x0};  // It will set to the syscalls at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

unsigned long the_ni_syscall;

// -------------------------- MODULE FUNCTIONS -------------------------

/**
 * @brief Checks whether the thread has root privilige or not and if the input
 * password is correct.
 *
 * @param input_password: user password to check
 * @param max_size: password max size
 * @return 0 if all checks are passed, an error otherwise.
 */
static int checkPasswordAndPermission(char __user *input_password,
                                      long max_size) {
    char *k_password;  // Kernel space pointer that store the password

    // If the thread is not root, return permission error
    if (!isRoot()) {
        printk(KERN_ERR "%s: state change attempted from a non-root thread.\n",
               MODNAME);
        return -EPERM;
    }

    k_password = get_user_string(input_password, MAX_PASSWD_LENGHT);
    if (IS_ERR(k_password)) {
        printk(KERN_ERR
               "%s: input password cannot be copied in a kernel buffer. Error: "
               "%ld\n",
               MODNAME, PTR_ERR(k_password));
        return -EINVAL;
    }

    // Password check
    if (verify_password(k_password, strlen(k_password), hashed_password) != 0) {
        printk(KERN_ERR "%s: invalid password.\n", MODNAME);
        return -EINVAL;
    }

    return 0;
}

// -------------------------- MODULE SYSCALLS --------------------------

/**
 * @brief change the reference monitor state to new_state.
 *
 * @param new_state: the new state for the monitor. The possible states are: ON,
 * OFF, REC-ON or REC-OFF.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _change_monitor_state, char __user *, input_password, int,
                  new_state) {
#else
asmlinkage long sys_change_monitor_state(char __user *input_password,
                                         int new_state) {
#endif
    state old_state;
    int ret;

    AUDIT
    printk("%s: request to change state to state %d\n", MODNAME, new_state);

    if ((ret = checkPasswordAndPermission(input_password, MAX_PASSWD_LENGHT)) !=
        0)
        return ret;

    AUDIT
    printk("%s: password successfully verified\n", MODNAME);

    // Check if the argument is a valid state
    if (!isAValidState(new_state)) {
        printk(KERN_ERR "%s: invalid input state (%d)\n", MODNAME, new_state);
        return -EINVAL;
    }

    old_state = change_monitor_state((state)new_state);

    AUDIT
    printk("%s: state successfully changed from %s to %s\n", MODNAME,
           state_to_string(old_state), state_to_string(new_state));

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(1, _show_monitor_state, char __user *, input_password) {
#else
asmlinkage long sys_show_monitor_state(char __user *input_password) {
#endif
    int ret;

    if ((ret = checkPasswordAndPermission(input_password, MAX_PASSWD_LENGHT)) !=
        0)
        return ret;

    print_monitor_state();

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(3, _add_remove_protected_path, char __user *, input_password,
                  char __user *, input_path, enum mode, input_mode) {
#else
asmlinkage long sys_add_remove_protected_path(char __user *input_password,
                                              char __user *input_path,
                                              enum mode input_mode) {
#endif
    char *k_path_str;
    struct path k_path;
    int ret;

    // Check password and permission
    if ((ret = checkPasswordAndPermission(input_password, MAX_PASSWD_LENGHT)) !=
        0)
        return ret;

    // Retrieve input_path
    k_path_str = get_user_string(input_path, PATH_MAX);
    if (IS_ERR(k_path_str)) {
        printk(KERN_ERR "%s: Failed to resolve path.\n", MODNAME);
        return -EINVAL;
    }

    if ((ret = kern_path(k_path_str, LOOKUP_FOLLOW, &k_path)) != 0) {
        if (ret == -ENOENT) {
            // Path does not exist
            printk(KERN_ERR "%s: The input path does not exist: '%s'.\n",
                   MODNAME, k_path_str);
            kfree(k_path_str);
            return -EINVAL;
        } else if (ret == -EACCES) {
            // The program does not have the permission to access the path
            printk(KERN_ERR "%s: Permission denied accessing the input path.\n",
                   MODNAME);
            kfree(k_path_str);
            return -EPERM;
        } else {
            printk(KERN_ERR "%s: Failed to resolve path '%s'\n", MODNAME,
                   k_path_str);
            kfree(k_path_str);
            return -EINVAL;
        }
    }

    ret = 0;

    switch (input_mode) {
        case ADD:
            // Add the path to the protected ones
            AUDIT
            printk(KERN_INFO "%s: Adding a protected path...\n", MODNAME);

            ret = add_protected_path(k_path);
            if (ret == 1) {
                // PATH ALREADY EXISTS
                printk(KERN_INFO "%s: Path is already protected.\n", MODNAME);
                ret = 0;  // Path is already protected, so no problem. This
                          // operation is useless since ret is already 0, but it
                          // makes more clear the code.
                break;
            } else if (ret == -1) {
                // KMALLOC ERROR
                printk(KERN_ERR
                       "%s: Impossible to allocate a buffer for the new path.",
                       MODNAME);
                break;
            } else if (ret == -2) {
                // MONITOR NOT RECONFIGURABLE
                printk(KERN_ERR
                       "%s: The reference monitor is in an unmodifiable state: "
                       "%s.\n",
                       MODNAME, state_to_string(get_monitor_state()));
                ret = -EPERM;
                break;
            }

            AUDIT
            printk(KERN_INFO "%s: Path successfully added: '%s'.\n", MODNAME,
                   k_path_str);

            break;
        case REMOVE:
            // Remove the path from the protected ones
            AUDIT
            printk(KERN_INFO "%s: Removing a protected path...\n", MODNAME);

            ret = remove_protected_path(k_path);
            if (ret == -1) {
                // NOT FOUND
                printk(KERN_ERR
                       "%s: Path not found. Is the path protected? Path: '%s'",
                       MODNAME, k_path_str);
                ret = -EINVAL;
                break;
            } else if (ret == -2) {
                // MONITOR NOT RECONFIGURABLE
                printk(KERN_ERR
                       "%s: The reference monitor is in an unmodifiable state: "
                       "%s.\n",
                       MODNAME, state_to_string(get_monitor_state()));
                ret = -EPERM;
                break;
            }

            AUDIT
            printk(KERN_INFO "%s: Path successfully deleted: '%s'\n", MODNAME,
                   k_path_str);

            break;
        default:
            printk(KERN_ERR
                   "%s: The input mode is invalid. Use the mode enum to "
                   "choose ADD or REMOVE.\n",
                   MODNAME);
            ret = -EINVAL;
            break;
    }

    path_put(&k_path);
    kfree(k_path_str);

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_change_monitor_state = (unsigned long)__x64_sys_change_monitor_state;
long sys_show_monitor_state = (unsigned long)__x64_sys_show_monitor_state;
long sys_add_remove_protected_path =
    (unsigned long)__x64_sys_add_remove_protected_path;
#endif

int init_module(void) {
    int i;
    int ret;

    if (the_syscall_table == 0x0) {
        printk(KERN_ERR "%s: cannot manage sys_call_table address set to 0x0\n",
               MODNAME);
        return -1;
    }

    AUDIT {
        printk("%s: queuing example received sys_call_table address %px\n",
               MODNAME, (void *)the_syscall_table);
        printk("%s: initializing - hacked entries %d\n", MODNAME,
               HACKED_ENTRIES);
    }

    // REMEMBER to update the array size
    new_sys_call_array[0] = (unsigned long)sys_change_monitor_state;
    new_sys_call_array[1] = (unsigned long)sys_show_monitor_state;
    new_sys_call_array[2] = (unsigned long)sys_add_remove_protected_path;

    ret = get_entries(restore, HACKED_ENTRIES,
                      (unsigned long *)the_syscall_table, &the_ni_syscall);

    if (ret != HACKED_ENTRIES) {
        printk(KERN_ERR "%s: could not hack %d entries (just %d)\n", MODNAME,
               HACKED_ENTRIES, ret);
        return -1;
    }

    unprotect_memory();

    for (i = 0; i < HACKED_ENTRIES; i++) {
        ((unsigned long *)the_syscall_table)[restore[i]] =
            (unsigned long)new_sys_call_array[i];
    }

    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n",
           MODNAME);

    printk("%s: sys_change_monitor_state installed on %d\n", MODNAME,
           restore[0]);
    printk("%s: sys_show_monitor_state installed on %d\n", MODNAME, restore[1]);
    printk("%s: sys_add_remove_protected_path installed on %d\n", MODNAME,
           restore[2]);

    // VARIABLE INITIALIZATION

    initialize_monitor_state();

    // PASSWORD ENCRYPTION

    ret = compute_crypto_digest(the_password, strlen(the_password),
                                hashed_password);
    if (ret) {
        printk(KERN_ERR "%s: password encryption failed\n", MODNAME);
        return ret;
    }

    AUDIT
    printk("%s: password digest computed\n", MODNAME);

    // KRETPROBES REGISTRATION

    if (!register_my_kretprobes()) {
        printk(KERN_ERR "%s: kretprobes registration failed. \n", MODNAME);
        return -1;
    }

    AUDIT
    printk(KERN_INFO "%s: all the kretprobes are successfully registered.\n",
           MODNAME);

    return 0;
}

void cleanup_module(void) {
    int i;

    printk("%s: shutting down\n", MODNAME);

    unprotect_memory();
    for (i = 0; i < HACKED_ENTRIES; i++) {
        ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
    }
    protect_memory();
    printk("%s: sys-call table restored to its original content\n", MODNAME);

    unregister_my_kretprobes();
    printk("%s: kretprobes unregistered\n", MODNAME);
}