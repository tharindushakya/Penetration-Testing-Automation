CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lm
LDFLAGS_GUI = -lgdi32 -luser32 -lkernel32 -lshell32 -lm

SRC_DIR = src
OBJ_DIR = build
BIN_CLI = SecureScan-CLI
BIN_GUI = SecureScan-Pro

# Source files
CORE_SRCS = $(SRC_DIR)/engine.c $(SRC_DIR)/ruleset.c $(SRC_DIR)/report.c $(SRC_DIR)/ai_detector.c
CLI_SRCS = $(CORE_SRCS) $(SRC_DIR)/main.c
GUI_SRCS = $(CORE_SRCS) $(SRC_DIR)/gui.c

# Object files
CLI_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(CLI_SRCS))
GUI_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/gui_%.o,$(GUI_SRCS))

.PHONY: all clean run cli gui

all: $(OBJ_DIR) $(BIN_CLI) $(BIN_GUI)

cli: $(OBJ_DIR) $(BIN_CLI)

gui: $(OBJ_DIR) $(BIN_GUI)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_CLI): $(CLI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_GUI): $(GUI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_GUI)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/gui_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

run-cli: $(BIN_CLI)
	./$(BIN_CLI)

run-gui: $(BIN_GUI)
	./$(BIN_GUI)

clean:
	rm -rf $(OBJ_DIR) $(BIN_CLI) $(BIN_GUI)
