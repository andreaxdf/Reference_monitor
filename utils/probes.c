#include "include/probes.h"

#define DEFINE_POST_HANDLER(name)                                   \
    static int post_handler_##name(struct kretprobe_instance *ri,   \
                                   struct pt_regs *regs) {          \
        regs->ax = (unsigned long)-EACCES;                          \
        AUDIT                                                       \
        printk("%s-PROBE-%s: %s denied.\n", MODNAME, #name, #name); \
        return 0;                                                   \
    }

#define DEFINE_KRTPROBE_STRUCT(name)                    \
    static struct kretprobe kretprobe_struct_##name = { \
        .kp.symbol_name = "security_path_" #name,       \
        .handler = post_handler_path_##name,            \
        .entry_handler = pre_handler_path_##name,       \
    };

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
 * (if the operation had not been denied). It can be NULL, if the reason is
 * different from RENAME.
 */
static void schedule_deferred_log(intrusion_type reason, struct path *main_path,
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
               "%s-PROBE: impossible to allocate buffer for deferred work "
               "objects\n",
               MODNAME);
        return;
    }

    if (!curr_exe_pathname) {
        printk(KERN_ERR
               "%s-PROBE: impossible to retrieve the current executable "
               "pathname\n",
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

void print_accessed_path(struct path *protected_path) {
    char *buff, *pathname;

    buff = kmalloc(PATH_MAX, GFP_KERNEL);
    pathname = d_path(protected_path, buff, PAGE_SIZE);

    if (IS_ERR(pathname)) {
        printk(KERN_ERR "%s-PROBE: error retrieving the path string.\n",
               MODNAME);
    } else {
        AUDIT
        printk("%s-PROBE: accessed path: '%s'.\n", MODNAME, pathname);
    }

    kfree(buff);
}

void handle_intrusion_two_paths(intrusion_type reason, struct path *old_path,
                                struct path *new_path, bool old) {
    struct path *protected_path;

    // Get the protected path
    if (old)
        protected_path = old_path;
    else
        protected_path = new_path;

    print_accessed_path(protected_path);

    schedule_deferred_log(reason, old_path, new_path);

    return;
}

// ------------------------------- KRETPROBES -------------------------------

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
        AUDIT
        printk("%s-PROBE_RENAME: protected path renaming detected.\n", MODNAME);

        // Get old entry path
        old_path.dentry = old_dentry;
        old_path.mnt = old_dir->mnt;
        // Get new entry path
        new_path.dentry = new_dentry;
        new_path.mnt = new_dir->mnt;

        handle_intrusion_two_paths(RENAME, &old_path, &new_path, old);

        return 0;
    }

    // Don't overwrite the return value (and deny the operation), if neither
    // path is protected.
    return 2;
}

DEFINE_POST_HANDLER(path_rename)

DEFINE_KRTPROBE_STRUCT(rename)

/**
 * @brief Handle intrusions that have only one path.
 *
 * @param reason the reason of the intrusion
 */
void handle_intrusion_one_path(intrusion_type reason,
                               struct path *protected_path) {
    print_accessed_path(protected_path);

    schedule_deferred_log(reason, protected_path, NULL);

    return;
}

static int pre_handler_path_unlink(struct kretprobe_instance *ri,
                                   struct pt_regs *regs) {
    struct path *dir;
    struct dentry *dentry;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *dir
    dir = (struct path *)regs->di;
    // rsi contains the second parameter -> struct dentry *dentry
    dentry = (struct dentry *)regs->si;

    if (is_path_protected(dentry)) {
        struct path path;

        AUDIT
        printk("%s-PROBE_UNLINK: protected path unlinking detected.\n",
               MODNAME);

        path.dentry = dentry;
        path.mnt = dir->mnt;

        handle_intrusion_one_path(DELETE, &path);

        return 0;
    }

    // Don't overwrite the return value (and deny the operation), if the path is
    // not protected.
    return 1;
}

DEFINE_POST_HANDLER(path_unlink)

DEFINE_KRTPROBE_STRUCT(unlink)

/**
 * @brief Hanlder to avoid the creation of symbolic links to the protected files
 * (otherwise anyone can use the symbolic links to access them)
 */
static int pre_handler_path_symlink(struct kretprobe_instance *ri,
                                    struct pt_regs *regs) {
    struct path *symlink_dir;
    struct dentry *symlink_dentry;
    char *file_target_name;
    bool old, new = false;

    struct path old_path;  // path to the target of the symbolic link

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *dir, the dir in which
    // the symbolic link will be created
    symlink_dir = (struct path *)regs->di;
    // rsi contains the second parameter -> struct dentry *dentry, the dentry
    // that represent the new hard link
    symlink_dentry = (struct dentry *)regs->si;
    // rdx contains the third parameter -> char *old_name, path to the target
    // of the symbolic link
    file_target_name = (char *)regs->dx;

    // Retrieve the symlink filepath to check
    if (kern_path(file_target_name, LOOKUP_FOLLOW, &old_path) != 0) {
        if (kern_path(strcat(file_target_name, "~"), LOOKUP_FOLLOW,
                      &old_path) != 0) {
            // printk(KERN_ERR
            //        "%s-PROBE_SYMLINK: impossible to retrieve the old_path: "
            //        "'%s'.\n",
            //        MODNAME, file_target_name);
            return 1;
        }
    } else {
        AUDIT
        printk("%s-PROBE_SYMLINK: old_path = '%s'.\n", MODNAME,
               file_target_name);
    }

    old = is_path_protected(old_path.dentry);      // Check the target path
    new = is_path_protected(symlink_dir->dentry);  // Check the new path

    if (old || new) {
        struct path symlink_path;

        AUDIT
        printk("%s-PROBE_SYMLINK: protected path unlinking detected.\n",
               MODNAME);

        symlink_path.dentry = symlink_dentry;
        symlink_path.mnt = symlink_dir->mnt;

        handle_intrusion_two_paths(SYMB_LINK, &old_path, &symlink_path, old);

        path_put(&old_path);

        return 0;
    }

    path_put(&old_path);

    // Don't overwrite the return value (and deny the operation), if the path is
    // not protected.
    return 1;
}

DEFINE_POST_HANDLER(path_symlink)

DEFINE_KRTPROBE_STRUCT(symlink)

/**
 * @brief Hanlder to avoid the creation of hard links to the protected files.
 */
static int pre_handler_path_link(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
    struct path *new_dir;
    struct dentry *old_dentry;
    struct dentry *new_dentry;

    bool old, new = false;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct dentry *old_dentry, the dentry
    // to the original file
    old_dentry = (struct dentry *)regs->di;
    // rsi contains the second parameter -> struct path *new_dir, the directory
    // path where the new hard link will be created.
    new_dir = (struct path *)regs->si;
    // rdx contains the third parameter -> struct dentry *new_dentry, the dentry
    // to the new hard link
    new_dentry = (struct dentry *)regs->dx;

    old = is_path_protected(old_dentry);  // Check the target path
    new = is_path_protected(new_dentry);  // Check the new path

    if (old || new) {
        struct path new_path;
        struct path old_path;

        AUDIT
        printk("%s-PROBE_LINK: protected path unlinking detected.\n", MODNAME);

        old_path.dentry = old_dentry;
        // Assuming that they are in the same mount point -> hard links can be
        // created only in the same mount point
        old_path.mnt = new_dir->mnt;

        new_path.dentry = new_dentry;
        new_path.mnt = new_dir->mnt;

        handle_intrusion_two_paths(HARD_LINK, &old_path, &new_path, old);

        return 0;
    }

    // Don't overwrite the return value (and deny the operation), if the path is
    // not protected.
    return 1;
}

DEFINE_POST_HANDLER(path_link)

DEFINE_KRTPROBE_STRUCT(link)

/**
 * @brief Hanlder to avoid the removal of a protected directory.
 */
static int pre_handler_path_rmdir(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
    struct path *parent_dir;
    struct dentry *target_dentry;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *dir, the dir that
    // contain the dir to delete
    parent_dir = (struct path *)regs->di;
    // rsi contains the second parameter -> struct dentry *dentry, the dentry
    // of the target dir to delete
    target_dentry = (struct dentry *)regs->si;

    if (is_path_protected(target_dentry)) {
        struct path target_path;

        AUDIT
        printk("%s-PROBE_RMDIR: protected path removal detected.\n", MODNAME);

        target_path.dentry = target_dentry;
        target_path.mnt = parent_dir->mnt;

        handle_intrusion_one_path(DELETE, &target_path);

        return 0;
    }

    // Don't overwrite the return value (and deny the operation), if the path is
    // not protected.
    return 1;
}

DEFINE_POST_HANDLER(path_rmdir)

DEFINE_KRTPROBE_STRUCT(rmdir)

/**
 * @brief Hanlder to avoid the creation of directory in a protected path.
 */
static int pre_handler_path_mkdir(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
    struct path *parent_dir;
    struct dentry *target_dentry;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *dir, the dir that
    // contain the dir to delete
    parent_dir = (struct path *)regs->di;
    // rsi contains the second parameter -> struct dentry *dentry, the dentry
    // of the target dir to delete
    target_dentry = (struct dentry *)regs->si;

    if (is_path_protected(target_dentry)) {
        struct path target_path;

        AUDIT
        printk(
            "%s-PROBE_MKDIR: attempt to create a new dir in a protected path "
            "detected.\n",
            MODNAME);

        target_path.dentry = target_dentry;
        target_path.mnt = parent_dir->mnt;

        handle_intrusion_one_path(CREATE, &target_path);

        return 0;
    }

    // Don't overwrite the return value (and deny the operation), if the path is
    // not protected.
    return 1;
}

DEFINE_POST_HANDLER(path_mkdir)

DEFINE_KRTPROBE_STRUCT(mkdir)

// int security_file_open(struct file *file, const struct cred *cred);

/**
 * @brief Hanlder to avoid the creation of directory in a protected path.
 */
static int pre_handler_file_open(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
    struct file *file;
    struct path *path;
    int access_mode;
    bool is_writing;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    // rdi contains the first parameter -> struct path *dir, the dir that
    // contain the dir to delete
    file = (struct file *)regs->di;

    path = &file->f_path;
    // Increment the reference counter, otherwise the dentry or the
    // vfsmount might be freed
    path_get(path);
    access_mode = file->f_flags & O_ACCMODE;

    is_writing = access_mode != O_RDONLY;

    if (is_writing && is_path_protected(path->dentry)) {
        AUDIT
        printk("%s-PROBE_OPEN: protected path open in write mode detected.\n",
               MODNAME);

        handle_intrusion_one_path(WRITE_ON_FILE, path);

        path_put(path);

        return 0;
    }

    path_put(path);

    // Don't overwrite the return value (and deny the operation), if the path is
    // not protected.
    return 1;
}

DEFINE_POST_HANDLER(file_open)

static struct kretprobe kretprobe_struct_open = {
    .kp.symbol_name = "security_file_open",
    .handler = post_handler_file_open,
    .entry_handler = pre_handler_file_open,
};

static struct kretprobe *my_kretprobes[] = {
    &kretprobe_struct_rename,  &kretprobe_struct_unlink,
    &kretprobe_struct_symlink, &kretprobe_struct_link,
    &kretprobe_struct_rmdir,   &kretprobe_struct_mkdir,
    &kretprobe_struct_open};

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