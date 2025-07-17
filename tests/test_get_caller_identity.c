#include <stdio.h>
#include <string.h>

#include "models/get_caller_identity.h"
#include "error.h"
#include "test_utils.h"

/**
 * @brief Tests deserialization of a full GetCallerIdentity XML response.
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

    int passed = err == ERROR_NONE &&
                 strcmp(identity.user_id, "AROAEXAMPLEID:user/test") == 0 &&
                 strcmp(identity.account, "123456789012") == 0 &&
                 strcmp(identity.arn.value, "arn:aws:sts::123456789012:assumed-role/AdminRole/test") == 0;

    print_test_result("test_get_caller_identity_all_fields", passed, err);
    return passed ? 0 : 1;
}

/**
 * @brief Tests deserialization with missing required field.
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

    int passed = err == ERROR_DESERIALIZE_MISSING_FIELD;
    print_test_result("test_get_caller_identity_missing_required", passed, err);
    return passed ? 0 : 1;
}

// === Test Runner ===

TestCase test_cases[] = {
    {"test_get_caller_identity_all_fields", test_get_caller_identity_all_fields},
    {"test_get_caller_identity_missing_required", test_get_caller_identity_missing_required},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
