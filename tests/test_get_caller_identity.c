#include <stdio.h>
#include <string.h>
#include "models/get_caller_identity.h"
#include "error.h"

/**
 * @brief Tests deserialization of a full GetCallerIdentity XML response.
 * @return 0 if passed, 1 if failed.
 */
int test_get_caller_identity_all_fields(void) {
    const char *xml =
        "<GetCallerIdentityResponse>"
            "<GetCallerIdentityResult>"
                "<UserId>AROAEXAMPLEID:user/test</UserId>"
                "<Account>123456789012</Account>"
                "<Arn>arn:aws:sts::123456789012:assumed-role/AdminRole/test</Arn>"
            "</GetCallerIdentityResult>"
        "</GetCallerIdentityResponse>"
        "<NotUsefullKey>TestContent</NotUsefullKey>";

    GetCallerIdentity identity = get_caller_identity_create();
    ErrorCode err = identity.vtable->deserialize_xml(&identity, xml);

    int passed = 1;
    passed &= err == ERROR_NONE;
    passed &= strcmp(identity.user_id, "AROAEXAMPLEID:user/test") == 0;
    passed &= strcmp(identity.account, "123456789012") == 0;
    passed &= strcmp(identity.arn.value, "arn:aws:sts::123456789012:assumed-role/AdminRole/test") == 0;


    if (passed) {
        printf("PASSED test_get_caller_identity_all_fields\n");
        return 0;
    } else {
        printf("FAILED test_get_caller_identity_all_fields\n");
        printf("Error code: %s\n", error_to_string(err));
        return 1;
    }
}

/**
 * @brief Tests deserialization of an XML with missing required field.
 * Should return an error.
 * @return 0 if passed (error correctly detected), 1 if failed.
 */
int test_get_caller_identity_missing_required(void) {
    const char *xml =
        "<GetCallerIdentityResponse>"
        "<GetCallerIdentityResult>"
        "<Account>987654321098</Account>"
        "<Arn>arn:aws:sts::987654321098:assumed-role/ReadOnlyRole/cli</Arn>"
        "</GetCallerIdentityResult>"
        "</GetCallerIdentityResponse>";

    GetCallerIdentity identity = get_caller_identity_create();
    ErrorCode err = identity.vtable->deserialize_xml(&identity, xml);

    if (err == ERROR_DESERIALIZE_MISSING_FIELD) {
        printf("PASSED test_get_caller_identity_missing_required\n");
        return 0;
    } else {
        printf("FAILED test_get_caller_identity_missing_required\n");
        printf("Unexpected error code: %s\n", error_to_string(err));
        return 1;
    }
}

// === Test runner ===

typedef int (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} TestCase;

TestCase test_cases[] = {
    {"test_get_caller_identity_all_fields", test_get_caller_identity_all_fields},
    {"test_get_caller_identity_missing_required", test_get_caller_identity_missing_required},
    {NULL, NULL}
};

/**
 * @brief Entry point for GetCallerIdentity model tests.
 * @return 0 if all tests pass, 1 otherwise.
 */
int main(int argc, char *argv[]) {
    int failed = 0;

    if (argc == 2) {
        const char *requested = argv[1];
        for (int i = 0; test_cases[i].name != NULL; i++) {
            if (strcmp(test_cases[i].name, requested) == 0) {
                return test_cases[i].func(); // run single test
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
