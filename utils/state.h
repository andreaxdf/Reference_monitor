#include <linux/types.h>

typedef enum _state {
    ON,
    OFF,
    REC_ON,
    REC_OFF,
} state;

bool isAValidState(state state);

const char *state_to_string(state state);