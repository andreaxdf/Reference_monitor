#include "include/utils.h"

/**
 * @brief Prints a formatted message with a printk.
 *
 * @param fmt: format string.
 * @param ...: parameters for the format string.
 */
void print_message(const char *fmt, ...) {
    va_list args;
    char formatted_msg[MAX_LOGMSG_LEN];
    char *log_msg;

    va_start(args, fmt);

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

/**
 * @brief Returns whether the current thread has root priority or not.
 */
bool isRoot(void) { return CURRENT_EUID == 0; }

/**
 * @brief Returns the user string in a dynamically allocated kernel buffer.
 *
 * @param user_string: string passed by user.
 * @return the user string in a kernel buffer or an error if something went
 * wrong. Check the return with IS_ERR macro.
 */
char *get_user_string(char __user *user_string, long max_size) {
    size_t str_len;
    char *kernel_string;

    str_len = strnlen_user(user_string, max_size);
    if (str_len == 0 || str_len > max_size) {
        printk("%s: Error getting user string size\n", MODNAME);
        return ERR_PTR(-EINVAL);
    }

    kernel_string = kmalloc(str_len, GFP_KERNEL);

    if (copy_from_user(kernel_string, user_string, str_len) != 0) {
        printk("%s: Error copying string from user\n", MODNAME);
        kfree(kernel_string);
        return ERR_PTR(-EFAULT);
    }

    return kernel_string;
}
