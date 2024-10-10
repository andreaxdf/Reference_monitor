#include "include/probes.h"

struct rename_data {
    struct path *old_path;
    struct path *new_path;
};

static int entry_handler_path_rename(struct kretprobe_instance *ri,
                                     struct pt_regs *regs) {
    struct rename_data *data;

    // Do nothing if the monitor is disabled
    if (!is_monitor_active()) return 1;

    data = (struct rename_data *)ri->data;

    // rdi contains the first parameter -> struct path *old_dir
    data->old_path = (struct dentry *)regs->di;
    data->new_path = (struct dentry *)regs->dx;
    return 0;
}

static int handler_path_rename(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
    struct krp_security_inode_rename_data *data =
        (struct krp_security_inode_rename_data *)ri->data;
    struct dentry *old_path = data->old_path;
    struct dentry *new_path = data->new_path;

    if (is_dentry_protected(old_path) || is_dentry_protected(new_path)) {
        char old_path_buf[PATH_MAX];
        char new_path_buf[PATH_MAX];
        char *old_pathname, *new_pathname;

        old_pathname = dentry_path_raw(old_path, old_path_buf, PATH_MAX);
        new_pathname = dentry_path_raw(new_path, new_path_buf, PATH_MAX);

        if (!IS_ERR(old_pathname) && !IS_ERR(new_pathname)) {
            old_pathname = kstrdup(old_pathname, GFP_KERNEL);
            new_pathname = kstrdup(new_pathname, GFP_KERNEL);
            submit_intrusion_log_work("DENIED RENAMING", old_pathname,
                                      new_pathname);
        } else {
            submit_intrusion_log_work("DENIED RENAMING", NULL, NULL);
        }
        regs->ax = (unsigned long)-EACCES;
        return 0;
    }

    return 0;
}

static struct kretprobe kretprobe_struct_rename = {
    .kp.symbol_name = "security_path_rename",
    .handler = handler_path_rename,
    .entry_handler = entry_handler_path_rename,
    .data_size = sizeof(struct rename_data),
};

static struct kretprobe *my_kretprobes[] = {
    &kretprobe_struct_rename,
};