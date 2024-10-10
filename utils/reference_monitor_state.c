#include "include/reference_monitor_state.h"

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
 * @brief Checks if kern_path (not any parent path) is already protected. The
 * function doesn't lock the monitor.
 *
 * @param kern_path path to check
 * @return true if the path is already protected, false otherwise
 */
static bool __is_path_already_protected(struct path kern_path) {
    protected_path *entry;

    list_for_each_entry(entry, &ref_monitor.protected_paths, list) {
        // Check if the dentry and the path already exist in the list
        if (kern_path.dentry == entry->actual_path.dentry &&
            kern_path.mnt == entry->actual_path.mnt) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Checks if kern_path or a parent path is protected. The
 * function lock the monitor.
 *
 * @param kern_path path to check
 * @return true if the path is already protected, false otherwise
 */
bool is_path_protected(struct path *kern_path) {
    protected_path *entry;
    struct dentry *curr_dentry = kern_path->dentry;
    struct vfsmount *curr_mnt = kern_path->mnt;

    spin_lock(&ref_monitor.monitor_lock);

    do {
        list_for_each_entry(entry, &ref_monitor.protected_paths, list) {
            // Check if the dentry and the path already exist in the list
            if (curr_dentry == entry->actual_path.dentry &&
                curr_mnt == entry->actual_path.mnt) {
                return true;
            }
        }

        curr_dentry = dget_parent(curr_dentry);
        // The vfsmount doesn't change in the cycle
    } while (!IS_ROOT(curr_dentry));

    spin_unlock(&ref_monitor.monitor_lock);

    return false;
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
    protected_path *new_path;

    spin_lock(&ref_monitor.monitor_lock);

    if (!is_monitor_reconfigurable()) {
        spin_unlock(&ref_monitor.monitor_lock);
        return -2;
    }

    if (__is_path_already_protected(kern_path)) {
        spin_unlock(&ref_monitor.monitor_lock);
        return 1;
    }

    new_path = kmalloc(sizeof(protected_path), GFP_KERNEL);
    if (!new_path) {
        spin_unlock(&ref_monitor.monitor_lock);
        return -1;
    }

    // Copying the path struct -> no out of scope problems should be met
    new_path->actual_path = kern_path;
    // new_path->inode = k_path.dentry->d_inode;
    INIT_LIST_HEAD(&(new_path->list));

    list_add(&(new_path->list), &ref_monitor.protected_paths);

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
    bool ret = -1;

    spin_lock(&ref_monitor.monitor_lock);

    if (!is_monitor_reconfigurable()) {
        spin_unlock(&ref_monitor.monitor_lock);
        return -2;
    }

    // Iterate over the list to find the path
    // Using the safe version since we must modify the list
    list_for_each_entry_safe(entry, tmp, &ref_monitor.protected_paths, list) {
        if (kern_path.dentry == entry->actual_path.dentry &&
            kern_path.mnt == entry->actual_path.mnt) {
            // Remove the item from the list
            list_del(&entry->list);

            // Free the memory
            kfree(entry);
            ret = 0;
            break;
        }
    }

    spin_unlock(&ref_monitor.monitor_lock);

    return ret;
}

state get_monitor_state(void) { return ref_monitor.state; }
