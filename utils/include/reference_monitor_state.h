#ifndef REF_MON_STATE_H
#define REF_MON_STATE_H

#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "constants.h"
#include "state.h"

typedef struct _protected_path {
    struct path actual_path;
    struct list_head list;
} protected_path;

void initialize_monitor_state(void);

state change_monitor_state(state new_state);

bool is_monitor_active(void);

bool is_path_protected(struct path *kern_path);

int add_protected_path(struct path kern_path);

int remove_protected_path(struct path kern_path);

void print_monitor_state(void);

state get_monitor_state(void);

#endif