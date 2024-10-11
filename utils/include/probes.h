#ifndef PROBES_H
#define PROBES_H

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

#include "intrusion_log.h"
#include "reference_monitor_state.h"

bool register_my_kretprobes(void);

void unregister_my_kretprobes(void);

bool enable_my_kretprobes(void);

bool disable_my_kretprobes(void);

#endif