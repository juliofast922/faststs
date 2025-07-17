#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "logger.h"
#include "test_utils.h"

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
    print_test_result("test_logger_stdout", 1, ERROR_NONE);
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

    print_test_result("test_logger_file_output", file_found, file_found ? ERROR_NONE : ERROR_UNKNOWN);
    return file_found ? 0 : 1;
}

// === Test Runner ===

TestCase test_cases[] = {
    {"test_logger_stdout", test_logger_stdout},
    {"test_logger_file_output", test_logger_file_output},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
