#include "include/intrusion_log.h"

#include "include/sha256_utils.h"

#define MODNAME "REFERENCE_MONITOR"
#define AUDIT if (1)
#define INTRUSION_DESCRIPTION_SIZE \
    PATH_MAX * 2 + 100  // The description may have at most 2 path and some
                        // other description string
#define LOG_PATH "/tmp/refmon_log/the-file"

#define SAFE_KFREE(ptr) \
    do {                \
        if (ptr) {      \
            kfree(ptr); \
            ptr = NULL; \
        }               \
    } while (0)

struct log_entry {
    char *description;            // intrusion description
    pid_t tgid;                   // TGID
    pid_t tid;                    // TID
    uid_t uid;                    // UID
    uid_t euid;                   // EUID
    char *pathname;               // Executable path-name
    char *executable_hashed_hex;  // Hexadecimal version of the resulting hash
                                  // of the executable
};

/**
 * @brief Execute the free of ptr and return a NULL pointer to
 *
 * @param ptr
 * @return void*
 */
void *cleanup(void *ptr) {
    if (ptr) kfree(ptr);

    return NULL;
}

/**
 * @brief Get the intrusion description of the log entry.
 *
 * @param intrusion_info: intrusion information
 * @param buffer: destination buffer
 * @param buffer_size: destination buffer size
 *
 * @return Return true if the description is written, false otherwise.
 *
 */
static int get_intrusion_description(struct intrusion_info *intrusion_info,
                                     char *buffer, size_t buffer_size) {
    int ret = -1;

    switch (intrusion_info->reason) {
        case WRITE_ON_FILE:
            ret = snprintf(buffer, buffer_size,
                           "Attempt to write on a protected file.\n"
                           "Protected path: %s\n",
                           intrusion_info->main_path);
            break;
        case RENAME:
            ret = snprintf(buffer, buffer_size,
                           "Attempt to rename a protected path.\n"
                           "Old path: %s\n"
                           "New path: %s\n",
                           intrusion_info->main_path,
                           intrusion_info->optional_path);
            break;
        case DELETE:
            ret = snprintf(buffer, buffer_size,
                           "Attempt to delete a protected path.\n"
                           "Protected path: %s\n",
                           intrusion_info->main_path);
            break;
        case CREATE:
            ret = snprintf(buffer, buffer_size,
                           "Attempt to create a file in a protected path.\n"
                           "File path: %s\n",
                           intrusion_info->main_path);
            break;
        case HARD_LINK:
            ret = snprintf(
                buffer, buffer_size,
                "Attempt to create a hard link in a protected path.\n"
                "Target path: %s\n"
                "Hard link path: %s\n",
                intrusion_info->main_path, intrusion_info->optional_path);
            break;
        case SYMB_LINK:
            ret = snprintf(
                buffer, buffer_size,
                "Attempt to create a symbolic link in a protected path.\n"
                "Target path: %s\n"
                "Symbolic link path: %s\n",
                intrusion_info->main_path, intrusion_info->optional_path);
            break;
    }

    return !(ret < 0);
}

/**
 * @brief Get the log message to write. Passing NULL as dst will return the size
 * of the message, terminator included.
 *
 * @param log_entry information to compose the log message.
 * @param dst destination buffer.
 * @return number of bytes required to store the message.
 */
int get_log_message(struct log_entry *log_entry, char *dst, size_t dst_size) {
    int lenght;

    lenght = snprintf(
        dst, dst_size,
        "\n---------------------------------------------------------\n"
        "Reason: %s\n"
        "TGID: %d, TID: %d, UID: %u, EUID: %u\n"
        "Intruder program pathname: %s\n"
        "Hash SHA256: %s\n"
        "---------------------------------------------------------\n",
        log_entry->description, log_entry->tgid, log_entry->tid, log_entry->uid,
        log_entry->euid, log_entry->pathname, log_entry->executable_hashed_hex);

    if (lenght < 0) return lenght;

    return lenght + 1;
}

int get_executable_hash(char *current_executable_path, char *exe_hashed_hex) {
    struct file *file;
    char *exe_content;
    loff_t pos = 0;
    unsigned char *exe_hashed;
    ssize_t numberOfBytesRead;
    loff_t exe_size;

    file = filp_open(current_executable_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(
            KERN_ERR
            "%s-DEFERRED WORK: Impossible to open the executable to log... the "
            "retrieved path was: %s",
            MODNAME, current_executable_path);
        return -1;
    }

    // Retrieve the executable size
    exe_size = vfs_llseek(file, 0, SEEK_END);
    if (exe_size < 0) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to retrieve the size of the "
               "executable to log.",
               MODNAME);
        filp_close(file, NULL);
        return -2;
    }

    vfs_llseek(file, 0, SEEK_SET);
    exe_content = kmalloc(exe_size + 1, GFP_KERNEL);
    if (!exe_content) {
        printk(
            KERN_ERR
            "%s-DEFERRED WORK: Impossible to allocate a buffer for the entire "
            "executable to log. file size = %lld\n",
            MODNAME, exe_size + 1);
        filp_close(file, NULL);
        return -3;
    }

    // Read the executable content
    numberOfBytesRead = kernel_read(file, exe_content, exe_size, &pos);
    if (numberOfBytesRead < 0) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to read the executable content.",
               MODNAME);
        filp_close(file, NULL);
        kfree(exe_content);
        return -4;
    }

    filp_close(file, NULL);
    exe_content[numberOfBytesRead] = '\0';

    // Compute the executable hash
    exe_hashed = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
    if (!exe_hashed) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to allocate a buffer to store the "
               "executable hash",
               MODNAME);
        kfree(exe_content);
        return -5;
    }

    if (compute_crypto_digest(exe_content, exe_size, exe_hashed)) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to read the executable content.",
               MODNAME);
        kfree(exe_content);
        kfree(exe_hashed);
        return -6;
    }

    // Convert hash to hexadecimal so it will have only readable chars
    bin2hex(exe_hashed_hex, exe_hashed, SHA256_DIGEST_SIZE);

    // Cleanup
    kfree(exe_content);
    kfree(exe_hashed);

    return 0;
}

/**
 * @brief Log an intrusion in the single file fs.
 *
 * @param work: work_struct
 */
void log_intrusion(struct work_struct *work) {
    struct intrusion_info *intrusion_info =
        container_of(work, struct intrusion_info, the_work);
    struct file *file;
    struct log_entry log_entry;
    char exe_hashed_hex[SHA256_DIGEST_SIZE * 2 +
                        1];  // store the hexadecimal version of the hash
    char *current_exe_path = NULL;
    char *description = NULL;
    char *message_buffer = NULL;

    int message_size;

    int ret;

    AUDIT
    printk("%s-DEFERRED WORK: start logging the intrusion\n", MODNAME);

    // Retrieve the executable path
    current_exe_path = intrusion_info->curr_exe_pathname;

    AUDIT
    printk("%s-DEFERRED WORK: executable pathname retrieved\n", MODNAME);

    if (get_executable_hash(current_exe_path, exe_hashed_hex) != 0) {
        goto cleanup;
    }

    AUDIT
    printk("%s-DEFERRED WORK: executable hash retrieved\n", MODNAME);

    description = kmalloc(INTRUSION_DESCRIPTION_SIZE, GFP_KERNEL);
    if (!description) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to allocate a buffer for the "
               "intrusion description.\n",
               MODNAME);
        goto cleanup;
    }

    ret = get_intrusion_description(intrusion_info, description,
                                    INTRUSION_DESCRIPTION_SIZE);
    if (ret < 0) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to create the log description. "
               "error = %d\n",
               MODNAME, ret);
        // Use a default description if something failed
        ret = snprintf(description, INTRUSION_DESCRIPTION_SIZE,
                       "Attempt to access a file in a protected path.\n");
    }

    AUDIT
    printk("%s-DEFERRED WORK: intrusion decscription retrieved\n", MODNAME);

    log_entry.description = description;               // Description
    log_entry.tgid = intrusion_info->tgid;             // T-GID
    log_entry.tid = intrusion_info->tid;               // TID
    log_entry.uid = intrusion_info->uid;               // UID
    log_entry.euid = intrusion_info->euid;             // EUID
    log_entry.pathname = current_exe_path;             // Pathname
    log_entry.executable_hashed_hex = exe_hashed_hex;  // Hash

    message_size = get_log_message(&log_entry, NULL, 0);
    if (message_size < 0) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to get the log message size. "
               "error = %d\n",
               MODNAME, message_size);
        goto cleanup;
    }

    message_buffer = kmalloc(message_size, GFP_KERNEL);
    if (!message_buffer) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to allocate a buffer for the "
               "log message.\n",
               MODNAME);
        goto cleanup;
    }

    message_size = get_log_message(&log_entry, message_buffer, message_size);
    if (message_size < 0) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to create the log message. "
               "error = %d\n",
               MODNAME, message_size);
        goto cleanup;
    }

    AUDIT
    printk("%s-DEFERRED WORK: log message retrieved\n", MODNAME);

    // Open log file
    file = filp_open(LOG_PATH, O_WRONLY | O_APPEND, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to open the log file. "
               "error = %ld\n",
               MODNAME, PTR_ERR(file));
        goto cleanup;
    }

    AUDIT
    printk("%s-DEFERRED WORK: file opened\n", MODNAME);

    // Write to the log file
    ret = kernel_write(file, message_buffer, message_size - 1, &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR
               "%s-DEFERRED WORK: Impossible to write the message in the log. "
               "error = %d\n",
               MODNAME, ret);
        filp_close(file, NULL);
        goto cleanup;
    }

    filp_close(file, NULL);

    AUDIT
    printk("%s-DEFERRED WORK: file closed\n", MODNAME);

    AUDIT
    printk(
        "%s-DEFERRED WORK: message written:\n"
        "\t%s\n",
        MODNAME, message_buffer);

cleanup:
    // Clean up
    SAFE_KFREE(description);
    SAFE_KFREE(message_buffer);
    SAFE_KFREE(intrusion_info->main_path);
    SAFE_KFREE(intrusion_info->optional_path);
    SAFE_KFREE(intrusion_info->curr_exe_pathname);
    SAFE_KFREE(intrusion_info);

    return;
}