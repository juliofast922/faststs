#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "error.h"

// Define primero el tipo TestCase
typedef struct {
    const char *name;
    int (*func)(void);
} TestCase;

// Luego las funciones que lo usan
void print_test_result(const char *test_name, int passed, ErrorCode err);
int run_test_by_name(const char *name, int (*func)(void), const char *expected_name);
int run_all_tests(int argc, char *argv[], const TestCase *tests);

#endif // TEST_UTILS_H
