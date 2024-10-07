#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define BLUE "\e[0;34m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

void get_string_from_user(char *buffer, int buffer_size, char *request_string);

void get_syscall_number_from_user(int *syscall_num, char *syscall_name);

void remove_new_line(char *str);

#endif