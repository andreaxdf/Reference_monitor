#ifndef LOG_H
#define LOG_H

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/workqueue.h>

typedef enum _intrusion_type {
    WRITE_ON_FILE,
    RENAME,
    DELETE,
    CREATE,
    HARD_LINK,
    SYMB_LINK,
} intrusion_type;

struct intrusion_info {
    intrusion_type reason;  // Operation that cause the intrusion
    char *main_path;        // Accessed path
    char *optional_path;    // Path used in case of renaming -> this would have
                            // been the new path
    pid_t tgid;
    pid_t tid;
    uid_t uid;
    uid_t euid;
    char *curr_exe_pathname;      // Pathname of the program which executes the
                                  // intrusion
    struct work_struct the_work;  // work_struct to pass to the work_queue
};

void log_intrusion(struct work_struct *work);

#endif