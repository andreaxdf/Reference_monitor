#include "include/intrusion_log.h"

/**
 * @brief Get the executable path object. NB: The returned buffer is dynamically
 * allocated, so it needs to be freed.
 *
 * @return Current executable path.
 */
char *get_current_executable_path(void) {
    struct file *exe_file;
    char *path;
    char *buf;
    struct path exe_path;

    // Get the executable file of the current process
    exe_file = get_task_exe_file(current);
    if (!exe_file) {
        printk(KERN_INFO "Unable to get executable file.\n");
        return NULL;
    }

    exe_path = exe_file->f_path;
    path_get(&exe_path);  // Increases the refcount of the path

    buf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Unable to allocate memory for path buffer.\n");
        return NULL;
    }

    path = d_path(&exe_path, buf, PATH_MAX);
    if (IS_ERR(path)) {
        printk(KERN_ERR "Unable to retrieve path.\n");
    } else {
        printk(KERN_INFO "Executable Path: %s\n", path);
    }

    // Clean up
    fput(exe_file);  // Decrease the refcount of the file structure

    return path;
}

/**
 * @brief Log an intrusion in the
 *
 * @param work: work_struct
 */
void log_intrusion(struct work_struct *work) {
    struct intrusion_info *log =
        container_of(work, struct intrusion_info, the_work);
    struct file *file;
    char *current_executable_path;
    loff_t program_size;

    current_executable_path = get_current_executable_path();
    if (current_executable_path == NULL) {
        printk("%s-DEFERRED WORK: Impossible to retrieve the program path...");
        return;
    }

    file = filp_open(current_executable_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(
            "%s-DEFERRED WORK: Impossible to open the program to log... the "
            "retrieved path "
            "was: %s",
            current_executable_path);
        goto cleanup;
    }
    program_size = vfs_llseek(file, 0, SEEK_END);
    if (program_size < 0) {
        printk(
            "%s-DEFERRED WORK: Impossible to retrieve the size of the program "
            "to log...");
        filp_close(file, NULL);
        goto cleanup;
    }
    // Clean up
    kfree(current_executable_path);
}