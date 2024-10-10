#ifndef CONSTANTS_H
#define CONSTANTS_H

#define MODNAME "REFERENCE_MONITOR"
#define AUDIT if (1)
#define MAX_PASSWD_LENGHT 50

#define CURRENT_EUID current_euid().val
#define CURRENT_TID current->pid
#define CURRENT_UID current_euid().val
#define CURRENT_TGID current->tgid

#endif