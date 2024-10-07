#ifndef ACTION_H
#define ACTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "utils.h"

typedef enum _action {
    SHOW_STATE,
    CHANGE_STATE,
    ADD_PATH,
    REMOVE_PATH,
    EXIT,

    LAST_ENTRY_ACTION
} action;

char *action_to_string(action chosen_action);

bool is_action_valid(action action);

void print_possible_actions();

action get_action_from_user();

#endif