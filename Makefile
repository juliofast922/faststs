# Variables
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
SRC = src/main.c src/utils.c
BIN = bin/fasts3sts
TEST_DIR = tests
TEST_BIN_DIR = bin/tests
TEST_FILES = $(wildcard $(TEST_DIR)/*.c)
UTILS = src/utils.c

# Default target
all: run

run: $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)
	@$(BIN)

test: $(TEST_FILES)
	@mkdir -p $(TEST_BIN_DIR)
	@for file in $^; do \
		name=$$(basename $$file .c); \
		echo "== Compile and execute $$name =="; \
		$(CC) $(CFLAGS) -o $(TEST_BIN_DIR)/$$name $$file $(UTILS) && $(TEST_BIN_DIR)/$$name || exit 1; \
	done

test_file:
	@mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CFLAGS) -o $(TEST_BIN_DIR)/$(file) $(TEST_DIR)/$(file).c $(UTILS)
	@$(TEST_BIN_DIR)/$(file)

test_func:
	@mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CFLAGS) -o $(TEST_BIN_DIR)/$(file) $(TEST_DIR)/$(file).c $(UTILS)
	@$(TEST_BIN_DIR)/$(file) $(func)

clean:
	rm -rf bin
