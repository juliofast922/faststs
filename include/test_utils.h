#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "error.h"

/**
 * @brief Represents a single unit test case.
 *
 * Each test has a name and a function pointer returning int (0 on success).
 */
typedef struct {
    const char *name;           /**< Name of the test case */
    int (*func)(void);          /**< Function pointer to the test case */
} TestCase;

/**
 * @brief Prints the result of a test case to stdout.
 *
 * @param test_name Name of the test.
 * @param passed 1 if the test passed, 0 otherwise.
 * @param err Optional error code returned by the test.
 */
void print_test_result(const char *test_name, int passed, ErrorCode err);

/**
 * @brief Runs a specific test function if the name matches.
 *
 * @param name The name provided at runtime.
 * @param func The test function pointer.
 * @param expected_name The name this test function is associated with.
 * @return 0 if test passes or does not match, 1 if test fails.
 */
int run_test_by_name(const char *name, int (*func)(void), const char *expected_name);

/**
 * @brief Executes all test cases, optionally filtering by test name via CLI args.
 *
 * @param argc Argument count from main().
 * @param argv Argument values from main().
 * @param tests Array of TestCase structures (must end with {NULL, NULL}).
 * @return 0 if all selected tests pass, 1 if any test fails.
 */
int run_all_tests(int argc, char *argv[], const TestCase *tests);

#endif // TEST_UTILS_H
