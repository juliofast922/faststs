#include <stdio.h>
#include <string.h>
#include "error.h"

/**
 * @brief Validates that each ErrorCode returns its expected string representation.
 *
 * @return int 0 if passed, 1 if failed.
 */
int test_error_to_string(void) {
    int passed = 1;

    passed &= strcmp(error_to_string(ERROR_NONE), "No error") == 0;
    passed &= strcmp(error_to_string(ERROR_DESERIALIZE_MISSING_FIELD), "Missing required field in XML") == 0;
    passed &= strcmp(error_to_string(ERROR_DESERIALIZE_INVALID_FORMAT), "Invalid XML format") == 0;
    passed &= strcmp(error_to_string(ERROR_UNKNOWN), "Unknown error") == 0;
    passed &= strcmp(error_to_string((ErrorCode)999), "Unknown error") == 0;

    if (passed)
        printf("PASSED test_error_to_string\n");
    else {
        printf("FAILED test_error_to_string\n");
        return 1;
    }

    return 0;
}

// Updated function pointer type to return int
typedef int (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} TestCase;

TestCase test_cases[] = {
    {"test_error_to_string", test_error_to_string},
    {NULL, NULL}
};

/**
 * @brief Entry point for Error module tests.
 *
 * Allows selective test execution by name, or runs all if no argument is provided.
 */
int main(int argc, char *argv[]) {
    int failed = 0;

    if (argc == 2) {
        const char *requested = argv[1];
        for (int i = 0; test_cases[i].name != NULL; i++) {
            if (strcmp(test_cases[i].name, requested) == 0) {
                return test_cases[i].func();  // Return 0 or 1 based on test result
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
