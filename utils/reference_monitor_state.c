#include "include/reference_monitor_state.h"

#define D_INODE_NUMBER(dentry) dentry->d_inode->i_ino
#define DEVICE_ID(dentry) dentry->d_inode->i_sb->s_dev

struct reference_monitor {
    state state;
    struct list_head protected_paths;
    spinlock_t monitor_lock;
};

static struct reference_monitor ref_monitor;

void initialize_monitor_state(void) {
    ref_monitor.state = REC_OFF;  // REC_OFF as default to configure the monitor

    INIT_LIST_HEAD(&ref_monitor.protected_paths);

    spin_lock_init(&ref_monitor.monitor_lock);
}

void print_monitor_state(void) {
    protected_path *entry;
    char *buff, *pathname;

    spin_lock(&ref_monitor.monitor_lock);

    printk("\n");
    printk("%s: Monitor state: %s\n", MODNAME,
           state_to_string(ref_monitor.state));
    printk("%s: The following paths are being protected:\n", MODNAME);

    list_for_each_entry(entry, &ref_monitor.protected_paths, list) {
        buff = (char *)__get_free_page(GFP_KERNEL);
        pathname = d_path(&(entry->actual_path), buff, PAGE_SIZE);

        if (IS_ERR(pathname))
            printk("\t\t\t\t error converting a path to string\n");
        else
            printk("\t\t\t\t %s\n", pathname);

        free_page((unsigned long)buff);
    }

    spin_unlock(&ref_monitor.monitor_lock);
}

static bool is_monitor_reconfigurable(void) {
    return ref_monitor.state == REC_ON || ref_monitor.state == REC_OFF;
}

bool is_monitor_active(void) {
    return ref_monitor.state == REC_ON || ref_monitor.state == ON;
}

/**
 * @brief Change the monitor state to new_state and return the old state. The
 * function lock the monitor.
 *
 * @param new_state the new reference monitor state
 * @return the old reference monitor state
 */
state change_monitor_state(state new_state) {
    state old_state;

    spin_lock(&ref_monitor.monitor_lock);

    old_state = ref_monitor.state;
    ref_monitor.state = new_state;

    spin_unlock(&ref_monitor.monitor_lock);

    return old_state;
}

/**
 * @brief Compare inode number and device number of the two paths. The inode is
 * unique only within the same file system, so we must compare also the
 * device_id to check if they are in the same file system.
 *
 * @return true if they have same inode number and same device id, false
 * otherwise
 */
static bool __compare_paths(struct dentry *d1, struct dentry *d2) {
    bool same_inode = D_INODE_NUMBER(d1) == D_INODE_NUMBER(d2);
    bool same_device = DEVICE_ID(d1) == DEVICE_ID(d2);

    return same_inode && same_device;
}

/**
 * @brief Checks if kern_path (not any parent path) is already protected. The
 * function doesn't lock the monitor.
 *
 * @param kern_path path to check
 * @return true if the path is already protected, false otherwise
 */
static bool __is_dentry_already_protected(struct dentry *kern_dentry) {
    protected_path *entry;

    // If the d_entry does not have an inode (e.g. it is used to rename a file),
    // the dentry is not protected.
    if (!kern_dentry->d_inode) return false;

    list_for_each_entry(entry, &ref_monitor.protected_paths, list) {
        // Check if the dentry and the path already exist in the list

        if (__compare_paths(kern_dentry, entry->actual_path.dentry)) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Checks if kern_path (not any parent path) is already protected. The
 * function doesn't lock the monitor.
 *
 * @param kern_path path to check
 * @return true if the path is already protected, false otherwise
 */
static bool __is_path_already_protected(struct path *kern_path) {
    return __is_dentry_already_protected(kern_path->dentry);
}

/**
 * @brief Checks if kern_path or a parent path is protected. The
 * function lock the monitor.
 *
 * @param kern_path path to check
 * @return true if the path is already protected, false otherwise
 */
bool is_path_protected(struct dentry *kern_dentry) {
    struct dentry *curr_dentry = kern_dentry;
    bool ret = false;

    spin_lock(&ref_monitor.monitor_lock);

    do {
        if (__is_dentry_already_protected(curr_dentry)) {
            ret = true;
            break;
        }

        curr_dentry = dget_parent(curr_dentry);
    } while (!IS_ROOT(curr_dentry));

    spin_unlock(&ref_monitor.monitor_lock);

    return ret;
}

/**
 * @brief Add the input path to the protected path list. The function lock the
 * monitor.
 *
 * @param kern_path path to add.
 * @return 0 if the path was added, an error otherwise:
 * Already present = 1;
 * Kmalloc error = -1;
 * Monitor not reconfigurable = -2;
 */
int add_protected_path(struct path kern_path) {
    protected_path *new_protected_path;

    spin_lock(&ref_monitor.monitor_lock);

    if (!is_monitor_reconfigurable()) {
        spin_unlock(&ref_monitor.monitor_lock);
        return -2;
    }

    if (__is_path_already_protected(&kern_path)) {
        spin_unlock(&ref_monitor.monitor_lock);
        return 1;
    }

    new_protected_path = kmalloc(sizeof(protected_path), GFP_KERNEL);
    if (!new_protected_path) {
        spin_unlock(&ref_monitor.monitor_lock);
        return -1;
    }

    // Copying the path struct -> no out of scope problems should be met
    new_protected_path->actual_path = kern_path;
    INIT_LIST_HEAD(&(new_protected_path->list));

    // Used to increment the reference counter of the objs dentry e vfsmount
    path_get(&kern_path);

    list_add(&(new_protected_path->list), &ref_monitor.protected_paths);

    spin_unlock(&ref_monitor.monitor_lock);

    return 0;
}

/**
 * @brief Removes the input path from the protected path list, if it exists. The
 * function lock the monitor.
 *
 * @param kern_path: path to remove.
 * @return 0 if the path was removed, an error otherwise:
 * Not found = -1;
 * Monitor not reconfigurable = -2;
 */
int remove_protected_path(struct path kern_path) {
    protected_path *entry, *tmp;
    int ret = -1;

    spin_lock(&ref_monitor.monitor_lock);

    if (!is_monitor_reconfigurable()) {
        spin_unlock(&ref_monitor.monitor_lock);
        return -2;
    }

    // Iterate over the list to find the path
    // Using the safe version since we must modify the list
    list_for_each_entry_safe(entry, tmp, &ref_monitor.protected_paths, list) {
        if (__compare_paths(kern_path.dentry, entry->actual_path.dentry)) {
            // Remove the item from the list
            list_del(&entry->list);

            // Free the memory
            path_put(&(
                entry->actual_path));  // Used to decrement the reference
                                       // counter of the objs dentry e vfsmount,
                                       // so that they can be released
            kfree(entry);
            ret = 0;
            break;
        }
    }

    spin_unlock(&ref_monitor.monitor_lock);

    return ret;
}

state get_monitor_state(void) { return ref_monitor.state; }
