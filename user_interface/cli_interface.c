#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "user_utils/include/action.h"
#include "user_utils/include/state.h"
#include "user_utils/include/utils.h"

#define RED "\x1B[31m"
#define PASSWORD "password"

int sys_change_monitor_state = 0;
int sys_show_monitor_state = 0;
int sys_add_remove_protected_path = 0;

void print_operation_result(int ret) {
    if (ret == 0)
        printf("Operation successfully executed.\n");
    else
        printf("Operation failed. error = %s\n", strerror(errno));
}

void show_state() {
    get_syscall_number_from_user(&sys_show_monitor_state,
                                 "sys_show_monitor_state");

    int ret = syscall(sys_show_monitor_state, PASSWORD);

    print_operation_result(ret);
}

void change_state() {
    state new_state;

    get_syscall_number_from_user(&sys_change_monitor_state,
                                 "sys_change_monitor_state");

    printf("Enter one of the following state:\n");

    new_state = get_state_from_user();

    int ret = syscall(sys_change_monitor_state, PASSWORD, new_state);

    print_operation_result(ret);
}

void add_path() {
    char path[512];

    get_syscall_number_from_user(&sys_add_remove_protected_path,
                                 "sys_add_remove_protected_path");

    get_string_from_user(path, 512,
                         YELLOW "Enter the path you want to protect: " RESET);
    remove_new_line(path);

    printf("Adding %s...\n", path);

    int ret = syscall(sys_add_remove_protected_path, PASSWORD, path, 0 /*ADD*/);

    print_operation_result(ret);
}

void remove_path() {
    char path[512];

    get_syscall_number_from_user(&sys_add_remove_protected_path,
                                 "sys_add_remove_protected_path");

    get_string_from_user(path, 512,
                         YELLOW "Enter the path you want to protect: " RESET);
    remove_new_line(path);

    printf("Removing %s...\n", path);

    int ret =
        syscall(sys_add_remove_protected_path, PASSWORD, path, 1 /*REMOVE*/);

    print_operation_result(ret);
}

int main() {
    action user_action;

    while (true) {
        user_action = get_action_from_user();

        switch (user_action) {
            case SHOW_STATE:
                show_state();
                break;
            case CHANGE_STATE:
                change_state();
                break;
            case ADD_PATH:
                add_path();
                break;
            case REMOVE_PATH:
                remove_path();
                break;
            case EXIT:
                return 0;
            default:
                break;
        }
    }

    return 0;
}
