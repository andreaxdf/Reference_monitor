#ifndef STATE_H
#define STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

typedef enum _state {
    ON,
    OFF,
    REC_ON,
    REC_OFF,

    LAST_ENTRY_STATE
} state;

const char *state_to_string(state state);

bool is_state_valid(state state);

void print_possible_states();

state get_state_from_user();

#endif