#include <stdio.h>
#include <string.h>
#include "utils.h"

void test_sum(void);

void test_sum(void) {
    int result = sum(2, 3);
    if (result == 5)
        printf("PASSED test_sum\n");
    else
        printf("FAILED test_sum\nExpected: 5 / Obtained: %d\n", result);
}

typedef void (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} TestCase;


TestCase test_cases[] = {
    {"test_sum", test_sum},
    {NULL, NULL} // Sentinel
};

int main(int argc, char *argv[]) {
    if (argc == 2) {
        const char *requested = argv[1];
        for (int i = 0; test_cases[i].name != NULL; i++) {
            if (strcmp(test_cases[i].name, requested) == 0) {
                test_cases[i].func();
                return 0;
            }
        }
        printf("Test not found '%s'\n", requested);
        return 1;
    }

    for (int i = 0; test_cases[i].name != NULL; i++) {
        test_cases[i].func();
    }

    return 0;
}