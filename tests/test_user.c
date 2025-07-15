#include <stdio.h>
#include <string.h>
#include "models/user.h"
#include "error.h"

/**
 * @brief Tests deserialization of a full AWS User XML.
 * @return 0 if passed, 1 if failed.
 */
int test_user_all_fields(void) {
    const char *xml =
        "<User>"
        "<UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>"
        "<Path>/division_abc/subdivision_xyz/</Path>"
        "<UserName>Bob</UserName>"
        "<Arn>arn:aws:iam::123456789012:user/division_abc/subdivision_xyz/Bob</Arn>"
        "<CreateDate>2013-10-02T17:01:44Z</CreateDate>"
        "<PasswordLastUsed>2014-10-10T14:37:51Z</PasswordLastUsed>"
        "</User>";

    User u = user_create();
    ErrorCode err = u.vtable->deserialize_xml(&u, xml);

    int passed = 1;
    passed &= err == ERROR_NONE;
    passed &= strcmp(u.user_id, "AIDACKCEVSQ6C2EXAMPLE") == 0;
    passed &= strcmp(u.path, "/division_abc/subdivision_xyz/") == 0;
    passed &= strcmp(u.user_name, "Bob") == 0;
    passed &= strcmp(u.arn, "arn:aws:iam::123456789012:user/division_abc/subdivision_xyz/Bob") == 0;
    passed &= strcmp(u.create_date, "2013-10-02T17:01:44Z") == 0;
    passed &= u.has_password_last_used;
    passed &= strcmp(u.password_last_used, "2014-10-10T14:37:51Z") == 0;

    if (passed) {
        printf("PASSED test_user_all_fields\n");
        return 0;
    } else {
        printf("FAILED test_user_all_fields\n");
        printf("Error code: %s\n", error_to_string(err));
        return 1;
    }
}

/**
 * @brief Tests deserialization of a User XML with missing optional fields.
 * @return 0 if passed, 1 if failed.
 */
int test_user_missing_optional_fields(void) {
    const char *xml =
        "<User>"
        "<UserId>UID123</UserId>"
        "<Path>/test/</Path>"
        "<UserName>Alice</UserName>"
        "<Arn>arn:aws:iam::111111111111:user/test/Alice</Arn>"
        "<CreateDate>2021-05-15T10:00:00Z</CreateDate>"
        "</User>";

    User u = user_create();
    ErrorCode err = u.vtable->deserialize_xml(&u, xml);

    int passed = 1;
    passed &= err == ERROR_NONE;
    passed &= strcmp(u.user_id, "UID123") == 0;
    passed &= strcmp(u.path, "/test/") == 0;
    passed &= strcmp(u.user_name, "Alice") == 0;
    passed &= strcmp(u.arn, "arn:aws:iam::111111111111:user/test/Alice") == 0;
    passed &= strcmp(u.create_date, "2021-05-15T10:00:00Z") == 0;
    passed &= u.has_password_last_used == 0;

    if (passed) {
        printf("PASSED test_user_missing_optional_fields\n");
        return 0;
    } else {
        printf("FAILED test_user_missing_optional_fields\n");
        printf("Error code: %s\n", error_to_string(err));
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
    {"test_user_all_fields", test_user_all_fields},
    {"test_user_missing_optional_fields", test_user_missing_optional_fields},
    {NULL, NULL}
};

/**
 * @brief Entry point for User model tests.
 * @return 0 if all tests pass, 1 otherwise.
 */
int main(int argc, char *argv[]) {
    int failed = 0;

    if (argc == 2) {
        const char *requested = argv[1];
        for (int i = 0; test_cases[i].name != NULL; i++) {
            if (strcmp(test_cases[i].name, requested) == 0) {
                return test_cases[i].func(); // retorna el resultado del test individual
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
