#include "include/action.h"

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
        case EXIT:
            return "Exit";
        default:
            return NULL;
    }
}

bool is_action_valid(action action) { return action < LAST_ENTRY_ACTION; }

void print_possible_actions() {
    printf("\n");

    for (int i = 0; i < LAST_ENTRY_ACTION; i++) {
        printf(BLUE "%d - %s\n" RESET, i, action_to_string(i));
    }

    printf("\n");
}

action get_action_from_user() {
    int input_action = -1;

    print_possible_actions();

    while (true) {
        char buffer[4];

        get_string_from_user(buffer, 4, YELLOW "Enter action number: " RESET);

        input_action = strtol(buffer, NULL, 10);

        if (is_action_valid(input_action)) {
            break;
        }

        printf("Invalid input\n");
    }

    return (action)input_action;
}