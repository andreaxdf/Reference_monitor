#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/types.h>

#define MODNAME "REFERENCE_MONITOR"
#define MAX_LOGMSG_LEN 256

void print_message(const char *fmt, ...);

bool isRoot();

#endif
