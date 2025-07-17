#include <stdio.h>
#include <string.h>
#include "test_utils.h"

void print_test_result(const char *test_name, int passed, ErrorCode err) {
    if (passed) {
        printf("\033[32mPASSED\033[0m %s\n", test_name);
    } else {
        printf("\033[31mFAILED\033[0m %s\n", test_name);
        if (err != ERROR_NONE) {
            printf("Error code: %s\n", error_to_string(err));
        }
    }
}

int run_test_by_name(const char *name, int (*func)(void), const char *expected_name) {
    if (strcmp(name, expected_name) == 0) {
        return func();
    }
    return -1;
}

int run_all_tests(int argc, char *argv[], const TestCase *tests) {
    int failed = 0;

    if (argc == 2) {
        const char *requested = argv[1];
        for (int i = 0; tests[i].name != NULL; i++) {
            if (strcmp(tests[i].name, requested) == 0) {
                return tests[i].func(); // Ejecuta test único
            }
        }
        printf("Test not found: '%s'\n", requested);
        return 1;
    }

    for (int i = 0; tests[i].name != NULL; i++) {
        if (tests[i].func() != 0)
            failed = 1;
    }

    return failed;
}
