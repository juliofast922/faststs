# Variables
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
SRC_DIR = src
SRC = $(filter-out $(SRC_DIR)/main.c, $(wildcard $(SRC_DIR)/**/*.c) $(wildcard $(SRC_DIR)/*.c))
BIN = bin/fasts3sts

TEST_DIR = tests
TEST_BIN_DIR = bin/tests
TEST_FILES = $(wildcard $(TEST_DIR)/*.c)

# Default target
all: run

# Run main app
run: $(SRC_DIR)/main.c $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(BIN) $(SRC_DIR)/main.c $(SRC)
	@$(BIN)

# Run all tests
test: $(TEST_FILES)
	@mkdir -p $(TEST_BIN_DIR)
	@for file in $^; do \
		name=$$(basename $$file .c); \
		echo "== Compile and execute $$name =="; \
		$(CC) $(CFLAGS) -o $(TEST_BIN_DIR)/$$name $$file $(SRC) && $(TEST_BIN_DIR)/$$name || exit 1; \
	done

# Run single test file
test_file:
	@mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CFLAGS) -o $(TEST_BIN_DIR)/$(file) $(TEST_DIR)/$(file).c $(SRC)
	@$(TEST_BIN_DIR)/$(file)

# Run single test function
test_func:
	@mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CFLAGS) -o $(TEST_BIN_DIR)/$(file) $(TEST_DIR)/$(file).c $(SRC)
	@$(TEST_BIN_DIR)/$(file) $(func)

clean:
	rm -rf bin
