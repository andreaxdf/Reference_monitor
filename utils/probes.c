#include "include/probes.h"

/**
 * @brief Schedule a new deferred work to write the intrusion in the log.
 *
 * @param reason Reason of the intrusion
 * @param main_path Main path accessed
 * @param optional_path In case of renaming, this would have been the new path
 * (if the operation had not been denied)
 */
// static void schedule_deferred_log(intrusion_type reason, char *main_path,
//                                   char *optional_path) {
//     struct intrusion_info *info;

//     // This struct is allocated here, but freed at the end of the deferred
//     work info = kmalloc(sizeof(struct intrusion_info), GFP_KERNEL);

//     info->reason = reason;
//     info->main_path = main_path;
//     info->optional_path = optional_path;
//     info->tgid = CURRENT_TGID;
//     info->tid = CURRENT_TID;
//     info->uid = CURRENT_UID;
//     info->euid = CURRENT_EUID;

//     INIT_WORK(&info->the_work, log_intrusion);
//     schedule_work(&info->the_work);
// }

/**
 * @brief Get the path string in dinamically allocated buffers.
 *
 * @param path path to retrieve
 * @return the path string retrieved from the path
 */
char *get_path_string(struct path *path) {
    char *buff, *path_str;

    if (!path) return NULL;

    buff = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buff) {
        return ERR_PTR(-ENOMEM);
    }

    // Retrieve the path strings given the path structs
    path_str = d_path(path, buff, PATH_MAX);

    // Copy the path string in a different buffer, so that the latter can be
    // freed -> Why? d_path can leave the initial bytes at 0, so without the
    // copy it would have been necessary to have both pointers (the buffer
    // address to free it and the address of the path string).
    path_str = kstrdup(path_str, GFP_KERNEL);

    // Free buffers
    kfree(buff);

    return path_str;
}

/**
 * @brief Schedule a new deferred work to write the intrusion in the log.
 *
 * @param reason Reason of the intrusion
 * @param main_path Main path accessed
 * @param optional_path In case of renaming, this would have been the new path
 * (if the operation had not been denied)
 */
static void schedule_deferred_log_with_path(intrusion_type reason,
                                            struct path *main_path,
                                            struct path *optional_path) {
    struct intrusion_info *info;
    char *main_path_str, *optional_path_str;

    // The info struct is allocated here, but freed at the end of the deferred
    // work (same for its fields)
    info = kmalloc(sizeof(struct intrusion_info), GFP_KERNEL);

    main_path_str = get_path_string(main_path);
    optional_path_str = get_path_string(optional_path);

    if (!info || IS_ERR(main_path_str) || IS_ERR(optional_path_str)) {
        printk(KERN_ERR
               "%s: impossible to allocate buffer for deferred work objects\n",
               MODNAME);
        return;
    }

    info->reason = reason;
    info->main_path = main_path_str;
    info->optional_path = optional_path_str;
    info->tgid = CURRENT_TGID;
    info->tid = CURRENT_TID;
    info->uid = CURRENT_UID;
    info->euid = CURRENT_EUID;

    INIT_WORK(&info->the_work, log_intrusion);
    schedule_work(&info->the_work);
}

/**
 * @brief kretprobe of security_path_rename. This function is used either for
 * renaming or moving a file, so it is important to check both, the old and the
 * new path (even additions to a protected path should be denied).
 *
 */
static int pre_handler_path_rename(struct kretprobe_instance *ri,
                                   struct pt_regs *regs) {
    struct path *old_path;
    struct path *new_path;
    struct path *protected_path;
    bool old, new;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *old_dir
    old_path = (struct path *)regs->di;
    // rdx contains the third parameter -> struct path *new_dir
    new_path = (struct path *)regs->dx;

    old = is_path_protected(old_path);
    new = is_path_protected(new_path);

    if (old || new) {
        char *buff;
        char *pathname;

        // Get the protected path
        if (old)
            protected_path = old_path;
        else
            protected_path = new_path;

        buff = (char *)__get_free_page(GFP_KERNEL);
        pathname = d_path(protected_path, buff, PAGE_SIZE);

        if (IS_ERR(pathname)) {
            AUDIT
            printk("%s-PROBE: renaiming of a protected path detected.\n",
                   MODNAME);
            printk(KERN_ERR "%s-PROBE: error retrieving the path string.\n",
                   MODNAME);
        } else {
            AUDIT
            printk("%s-PROBE: renaiming of a protected path detected: '%s'.\n",
                   MODNAME, pathname);
        }

        schedule_deferred_log_with_path(RENAME, old_path, new_path);

        free_page((unsigned long)buff);

        return 0;
    }

    // Don't overwrite the return value, if neither path is protected.
    return 2;
}

static int post_handler_path_rename(struct kretprobe_instance *ri,
                                    struct pt_regs *regs) {
    // Deny the access
    regs->ax = (unsigned long)-EACCES;

    AUDIT
    printk("%s-PROBE: rename denied.\n", MODNAME);

    return 0;
}

static struct kretprobe kretprobe_struct_rename = {
    .kp.symbol_name = "security_path_rename",
    .handler = post_handler_path_rename,
    .entry_handler = pre_handler_path_rename,
};

static struct kretprobe *my_kretprobes[] = {
    &kretprobe_struct_rename,
};

bool register_my_kretprobes(void) {
    int ret = register_kretprobes(my_kretprobes, ARRAY_SIZE(my_kretprobes));
    if (ret < 0) {
        AUDIT
        printk(KERN_ERR "%s: kretprobes registration failed. error = %d\n",
               MODNAME, ret);
        return false;
    }

    AUDIT
    printk(KERN_INFO "%s: all the kretprobes are successfully registered.\n",
           MODNAME);

    return true;
}

void unregister_my_kretprobes(void) {
    unregister_kretprobes(my_kretprobes, ARRAY_SIZE(my_kretprobes));

    AUDIT
    printk(KERN_INFO "%s: all the kretprobes are successfully unregistered.\n",
           MODNAME);

    return;
}