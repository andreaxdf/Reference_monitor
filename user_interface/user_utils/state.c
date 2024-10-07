#include "include/state.h"

const char *state_to_string(state state) {
    switch (state) {
        case ON:
            return "ON";
        case OFF:
            return "OFF";
        case REC_ON:
            return "REC-ON";
        case REC_OFF:
            return "REC-OFF";
        default:
            return NULL;
    }
}

bool is_state_valid(state state) { return state < LAST_ENTRY_STATE; }

void print_possible_states() {
    printf("\n");

    for (int i = 0; i < LAST_ENTRY_STATE; i++) {
        printf(BLUE "%d - %s\n" RESET, i, state_to_string(i));
    }

    printf("\n");
}

state get_state_from_user() {
    int input_state = -1;

    print_possible_states();

    while (true) {
        char buffer[10];

        get_string_from_user(buffer, 10, YELLOW "Enter state number: " RESET);

        input_state = strtol(buffer, NULL, 10);

        if (is_state_valid(input_state)) {
            break;
        }

        printf("Invalid state\n");
    }

    return (state)input_state;
}
