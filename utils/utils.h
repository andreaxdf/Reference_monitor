#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define MODNAME "REFERENCE_MONITOR"
#define MAX_LOGMSG_LEN 256

void print_message(const char *fmt, ...);

bool isRoot();

#endif
