#include <bool.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RED "\x1B[31m"

typedef enum _action {
    SHOW_STATE,
    CHANGE_STATE,
    ADD_PATH,
    REMOVE_PATH,

    LAST_ENTRY
} action;

char *action_to_string(action chosen_action) {
    switch (chosen_action) {
        case SHOW_STATE:
            return "Show monitor state";
        case CHANGE_STATE:
            return "Change monitor state";
        case ADD_PATH:
            return "Add a new path to protect";
        case REMOVE_PATH:
            return "Remove a protected path";
        default:
            return NULL;
    }
}

bool is_action_valid(action action) { return action < LAST_ENTRY; }

void print_options() {
    printf("\n");

    for (int i = 0; i < LAST_ENTRY; i++) {
        printf("%d - %s\n", i, action_to_string(i));
    }

    printf("\n");
}

action get_user_action() {
    action input_action;

    print_options();

    while (true) {
        char buffer[10];
        printf("Enter action number: ");
        while (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            printf("Invalid input\n");
        }

        input_action = strtol(buffer, NULL, 10);

        if (is_action_valid(input_action)) {
            break;
        }
    }

    return (action)input_action;
}

int main() {
    int syscall_number;
    char buffer[100];

    printf("Enter the syscall number: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Your input: %s");
    }

    int ret = syscall(syscall_number, param1, param2);
    if (ret != 0) {
        printf(RED "Syscall failed = %d. errno = %d: %s\n", ret, errno,
               strerror(errno));
        return 1;
    }

    printf("Syscall %d executed with ret=%d\n", syscall_, ret);

    return 0;
}
