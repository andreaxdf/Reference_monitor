#include "utils.h"

/**
 * @brief Prints a formatted message with a printk.
 *
 * @param fmt: format string
 * @param ...: parameters for the format string
 */
void print_message(const char *fmt, ...) {
    va_list args;
    char *log_msg;

    va_start(args, fmt);

    char formatted_msg[MAX_LOGMSG_LEN];
    vsnprintf(formatted_msg, sizeof(formatted_msg), fmt, args);

    va_end(args);

    log_msg = kasprintf(GFP_KERNEL, "%s: %s", MODNAME, formatted_msg);

    if (log_msg) {
        printk("%s", log_msg);
        kfree(log_msg);
    } else {
        printk("%s: Log message allocation failed\n", MODNAME);
    }
}

bool isRoot(void) { return CURRENT_EUID == 0; }