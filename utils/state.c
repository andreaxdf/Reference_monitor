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

bool isAValidState(state state) {
    switch (state) {
        case ON:
            break;
        case OFF:
            break;
        case REC_ON:
            break;
        case REC_OFF:
            break;
        default:
            return false;
    }
    return true;
}