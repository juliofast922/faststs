#include <string.h>
#include "models/user.h"
#include "error.h"
#include "test_utils.h"

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
        "</User>"
        "<NotUsefullKey>TestContent</NotUsefullKey>";

    User u = user_create();
    ErrorCode err = u.vtable->deserialize_xml(&u, xml);

    int passed = (err == ERROR_NONE) &&
                 strcmp(u.user_id, "AIDACKCEVSQ6C2EXAMPLE") == 0 &&
                 strcmp(u.path, "/division_abc/subdivision_xyz/") == 0 &&
                 strcmp(u.user_name, "Bob") == 0 &&
                 strcmp(u.arn.value, "arn:aws:iam::123456789012:user/division_abc/subdivision_xyz/Bob") == 0 &&
                 strcmp(u.create_date, "2013-10-02T17:01:44Z") == 0 &&
                 u.has_password_last_used &&
                 strcmp(u.password_last_used, "2014-10-10T14:37:51Z") == 0;

    print_test_result("test_user_all_fields", passed, err);
    return !passed;
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

    int passed = (err == ERROR_NONE) &&
                 strcmp(u.user_id, "UID123") == 0 &&
                 strcmp(u.path, "/test/") == 0 &&
                 strcmp(u.user_name, "Alice") == 0 &&
                 strcmp(u.arn.value, "arn:aws:iam::111111111111:user/test/Alice") == 0 &&
                 strcmp(u.create_date, "2021-05-15T10:00:00Z") == 0 &&
                 !u.has_password_last_used;

    print_test_result("test_user_missing_optional_fields", passed, err);
    return !passed;
}

/**
 * @brief Tests deserialization of a User XML with missing required field (UserName).
 * @return 0 if error correctly detected, 1 if failed.
 */
int test_user_missing_required_fields(void) {
    const char *xml =
        "<User>"
            "<UserId>UID999</UserId>"
            "<Path>/missing/</Path>"
            "<Arn>arn:aws:iam::000000000000:user/missing</Arn>"
            "<CreateDate>2020-01-01T00:00:00Z</CreateDate>"
        "</User>";

    User u = user_create();
    ErrorCode err = u.vtable->deserialize_xml(&u, xml);

    int passed = (err == ERROR_DESERIALIZE_MISSING_FIELD);
    print_test_result("test_user_missing_required_fields", passed, err);
    return !passed;
}

// === Test runner ===

TestCase test_cases[] = {
    {"test_user_all_fields", test_user_all_fields},
    {"test_user_missing_optional_fields", test_user_missing_optional_fields},
    {"test_user_missing_required_fields", test_user_missing_required_fields},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
