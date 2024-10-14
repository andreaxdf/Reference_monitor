#include "include/probes.h"

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
 * @brief Get the executable path object. NB: The returned buffer is dynamically
 * allocated, so it needs to be freed.
 *
 * @return Current executable path.
 */
static char *get_current_executable_path(void) {
    char *path_str;
    char *buf;
    struct file *exe_file;
    struct path *exe_path;

    // Get the executable file path of the current process
    exe_file = current->mm->exe_file;
    if (!exe_file) {
        printk(KERN_ERR "%s-PROBE: unable to get executable file.\n", MODNAME);
        return NULL;
    }

    exe_path = &exe_file->f_path;
    path_get(exe_path);  // Increases the refcount of the path

    buf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Unable to allocate memory for path buffer.\n");
        return NULL;
    }

    path_str = d_path(exe_path, buf, PATH_MAX);
    if (IS_ERR(path_str)) {
        printk(KERN_ERR "%s-PROBE: Unable to retrieve path.\n", MODNAME);
        path_put(exe_path);
        kfree(buf);
        return NULL;
    }

    path_str = kstrdup(path_str, GFP_KERNEL);
    if (!path_str) {
        printk(KERN_ERR "%s-PROBE: kstrdup failed.\n", MODNAME);
        return NULL;
    }

    AUDIT
    printk("%s-PROBE: intruder's pathname retrieved\n", MODNAME);

    // Clean up
    path_put(exe_path);  // Decrease the refcount of the file structure
    kfree(buf);          // The pathname is stored in the buf created by kstrdup

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
    char *curr_exe_pathname;

    // The info struct is allocated here, but freed at the end of the
    // deferred work (same for its fields)
    info = kmalloc(sizeof(struct intrusion_info), GFP_KERNEL);

    main_path_str = get_path_string(main_path);
    optional_path_str = get_path_string(optional_path);
    curr_exe_pathname = get_current_executable_path();

    if (!info || IS_ERR(main_path_str) || IS_ERR(optional_path_str)) {
        printk(KERN_ERR
               "%s: impossible to allocate buffer for deferred work objects\n",
               MODNAME);
        return;
    }

    if (!curr_exe_pathname) {
        printk(KERN_ERR
               "%s: impossible to retrieve the current executable pathname\n",
               MODNAME);
        return;
    }

    info->reason = reason;
    info->main_path = main_path_str;
    info->optional_path = optional_path_str;
    info->curr_exe_pathname = curr_exe_pathname;
    info->tgid = CURRENT_TGID;
    info->tid = CURRENT_TID;
    info->uid = CURRENT_UID;
    info->euid = CURRENT_EUID;

    INIT_WORK(&(info->the_work), log_intrusion);
    schedule_work(&(info->the_work));
}

struct dentry *lookup_dentry_already_exists(struct dentry *dentry,
                                            struct path *dir) {
    struct dentry *tmp_dentry;

    // is new_dentry going to overwrite another file?
    tmp_dentry =
        lookup_one_len(dentry->d_name.name, dir->dentry, dentry->d_name.len);

    if (IS_ERR(tmp_dentry)) return NULL;

    // Check if the target dentry has an associated inode (i.e., a file with the
    // same name exists)
    if (!tmp_dentry->d_inode) {
        // File not found
        return NULL;
    }

    return tmp_dentry;
}

/**
 * @brief kretprobe of security_path_rename. This function is used either for
 * renaming or moving a file, so it is important to check both, the old and the
 * new path (even additions to a protected path should be denied).
 *
 */
static int pre_handler_path_rename(struct kretprobe_instance *ri,
                                   struct pt_regs *regs) {
    struct path *old_dir;
    struct path *new_dir;
    struct dentry *old_dentry;
    struct dentry *new_dentry;
    struct dentry *tmp_dentry;

    struct path *protected_path;
    struct path old_path;
    struct path new_path;
    bool old, new, overwriting_protected_file = false;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *old_dir
    old_dir = (struct path *)regs->di;
    // rdx contains the third parameter -> struct path *new_dir
    new_dir = (struct path *)regs->dx;
    // rsi contains the second parameter -> struct dentry *old_dentry
    old_dentry = (struct dentry *)regs->si;
    // rcx contains the fourth parameter -> struct dentry *new_dentry
    new_dentry = (struct dentry *)regs->cx;
    if (!old_dentry || !new_dentry) return 1;

    // is new_dentry going to overwrite another file?
    tmp_dentry = lookup_dentry_already_exists(new_dentry, new_dir);

    if (tmp_dentry) {
        // Another file is going to be overwritten -> so check if this file is
        // protected
        overwriting_protected_file = is_path_protected(tmp_dentry);
    }

    // Check if the old entry is protected
    old = is_path_protected(old_dentry);
    // Check if the new directory is protected
    new = is_path_protected(new_dir->dentry);

    if (old || new || overwriting_protected_file) {
        char *buff;
        char *pathname;

        AUDIT
        printk("%s-PROBE: protected path renaming detected.\n", MODNAME);

        // Get old entry path
        old_path.dentry = old_dentry;
        old_path.mnt = old_dir->mnt;
        // Get new entry path
        new_path.dentry = new_dentry;
        new_path.mnt = new_dir->mnt;

        // Get the protected path
        if (old)
            protected_path = &old_path;
        else
            protected_path = &new_path;

        buff = kmalloc(PATH_MAX, GFP_KERNEL);
        pathname = d_path(protected_path, buff, PAGE_SIZE);

        if (IS_ERR(pathname)) {
            printk(KERN_ERR "%s-PROBE: error retrieving the path string.\n",
                   MODNAME);
        } else {
            AUDIT
            printk("%s-PROBE: accessed path: '%s'.\n", MODNAME, pathname);
        }

        schedule_deferred_log_with_path(RENAME, &old_path, &new_path);

        kfree(buff);

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

/**
 * @brief Register all the kretprobes of this module.
 *
 * @return true if registration succeeds, false otherwise
 */
bool register_my_kretprobes(void) {
    int ret = register_kretprobes(my_kretprobes, ARRAY_SIZE(my_kretprobes));
    if (ret < 0) {
        printk(KERN_ERR "%s: kretprobes registration failed. error = %d\n",
               MODNAME, ret);
        return false;
    }

    return true;
}

void unregister_my_kretprobes(void) {
    unregister_kretprobes(my_kretprobes, ARRAY_SIZE(my_kretprobes));

    return;
}

bool enable_my_kretprobes(void) {
    int i;
    for (i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
        int ret = enable_kretprobe(my_kretprobes[i]);
        if (ret < 0) {
            printk(KERN_INFO "%s: Impossible to enable kretprobe '%s'.\n",
                   MODNAME, my_kretprobes[i]->kp.symbol_name);
            return false;
        } else {
            printk(KERN_INFO "%s: kretprobe '%s' enabled.\n", MODNAME,
                   my_kretprobes[i]->kp.symbol_name);
        }
    }

    return true;
}

bool disable_my_kretprobes(void) {
    int i;
    for (i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
        int ret = disable_kretprobe(my_kretprobes[i]);
        if (ret < 0) {
            printk(KERN_INFO "%s: Impossible to disable kretprobe '%s'.\n",
                   MODNAME, my_kretprobes[i]->kp.symbol_name);
            return false;
        } else {
            printk(KERN_INFO "%s: kretprobe '%s' disabled.\n", MODNAME,
                   my_kretprobes[i]->kp.symbol_name);
        }
    }

    return true;
}