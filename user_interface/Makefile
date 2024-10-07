
TARGET = cli_interface

SRCS = cli_interface.c user_utils/action.c user_utils/state.c user_utils/utils.c
OBJS = $(SRCS:.c=.o)

CC = gcc

CFLAGS = -Wall -Wextra

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
