#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include "logger.h"

/**
 * @brief Tests logging to stdout only.
 *
 * @return int 0 if passed, 1 if failed.
 */
int test_logger_stdout(void) {
    logger_init(".env");
    logger_set_file_logging(0, 0); // Disable file logging

    log_debug("Message DEBUG (should be seen if LOG_LEVEL=DEBUG)");
    log_info("Message INFO");
    log_warn("Message WARN");
    log_error("Message ERROR");

    // Assume success if no crash
    printf("PASSED test_logger_stdout\n");
    return 0;
}

/**
 * @brief Tests that log messages are written to a file when enabled.
 *
 * @return int 0 if file found, 1 if not.
 */
int test_logger_file_output(void) {
    logger_init(".env");
    logger_set_file_logging(1, 10); // Enable file logging with short rotation

    log_info("This test message should be saved in a file");

    sleep(1); // Give time for the log file to be created

    // Check logs/ for any valid log file
    DIR *dir = opendir("logs");
    int file_found = 0;

    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, "log_") && strstr(entry->d_name, ".json")) {
                file_found = 1;
                break;
            }
        }
        closedir(dir);
    }

    if (file_found) {
        printf("PASSED test_logger_file_output\n");
        return 0;
    } else {
        printf("FAILED test_logger_file_output: Log file not found\n");
        return 1;
    }
}

// === Test runner ===

typedef int (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} TestCase;

// Table of available test cases
TestCase test_cases[] = {
    {"test_logger_stdout", test_logger_stdout},
    {"test_logger_file_output", test_logger_file_output},
    {NULL, NULL}
};

/**
 * @brief Entry point for logger tests.
 *
 * If called with an argument, runs only the named test.
 * Otherwise, executes all registered test functions.
 *
 * @return 0 on success, 1 on failure.
 */
int main(int argc, char *argv[]) {
    int failed = 0;

    if (argc == 2) {
        const char *requested = argv[1];
        for (int i = 0; test_cases[i].name != NULL; i++) {
            if (strcmp(test_cases[i].name, requested) == 0) {
                return test_cases[i].func();  // Return pass/fail
            }
        }
        printf("Test not found: '%s'\n", requested);
        return 1;
    }

    for (int i = 0; test_cases[i].name != NULL; i++) {
        if (test_cases[i].func() != 0)
            failed = 1;
    }

    return failed;
}
