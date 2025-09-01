CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -Iinclude
LDFLAGS = 

SRC_DIR = src
OBJ_DIR = build
BIN = pentest

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

.PHONY: all clean run

all: $(OBJ_DIR) $(BIN)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(BIN)
	./$(BIN)

clean:
	rm -rf $(OBJ_DIR) $(BIN)
