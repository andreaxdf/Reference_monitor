#ifndef UTILS_H
#define UTILS_H

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "constants.h"

#define MODNAME "REFERENCE_MONITOR"
#define MAX_LOGMSG_LEN 256

void print_message(const char *fmt, ...);

bool isRoot(void);

char *get_user_string(char __user *user_string, long max_size);

#endif
