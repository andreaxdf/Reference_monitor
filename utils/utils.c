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
        printk("%s%s: Log message allocation failed\n", log_level_str, MODNAME);
    }
}

bool isRoot() {
    return current_euid == 0;
}