#include "include/utils.h"

void clear_stdin() {
    char c;

    while ((c = getchar()) != '\n' && c != EOF); /* discard */
}

void get_string_from_user(char *buffer, int buffer_size, char *request_string) {
    printf(request_string);
    while (fgets(buffer, buffer_size, stdin) == NULL) {
        printf("Invalid input\n");
    }
}

void get_syscall_number_from_user(int *syscall_num, char *syscall_name) {
    char request_string[150];

    snprintf(
        request_string, sizeof(request_string),
        YELLOW
        "Enter %s number (the value will be saved for this session): " RESET,
        syscall_name);

    while (*syscall_num == 0) {
        char buffer[10];
        get_string_from_user(buffer, 10, request_string);

        *syscall_num = strtol(buffer, NULL, 10);

        if (*syscall_num < 0 || *syscall_num > 456) {
            printf("Invalid number: this is not a syscall number\n");
            *syscall_num = 0;
        }
    }
}

void remove_new_line(char *str) {
    if (str == NULL) return;

    for (int i = 0; i < (int)strlen(str); i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            return;
        }
    }
}
