#include <string.h>
#include <stdio.h>

#include "aws/sigv4.h"
#include "aws/credentials.h"
#include "error.h"
#include "test_utils.h"

/**
 * @brief Tests signature generation for a GET "/" with empty payload.
 * @return 0 if passed, 1 if failed.
 */
int test_sigv4_static_values(void) {
    AwsCredentials creds = {
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    };

    const char *amz_date = "20150830T123600Z";
    const char *date     = "20150830";
    const char *region   = "us-east-1";
    const char *service  = "iam";
    const char *signed_headers = "host;x-amz-date";

    // Note: no query string, empty payload => payload hash is e3b0c4…b855
    const char *canonical_request =
        "GET\n"
        "/\n"
        "\n"
        "host:iam.amazonaws.com\n"
        "x-amz-date:20150830T123600Z\n"
        "\n"
        "host;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    AuthorizationHeader auth = {0};
    ErrorCode err = authorization_header_build(
        &creds, amz_date, date, region, service, canonical_request, signed_headers, &auth
    );

    // this is the correct signature for the above request:
    const char *expected_signature =
        "AWS4-HMAC-SHA256 "
        "Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=91fb24346d00546d6da247c85eb79148080a6e3ae1ac9aa8eae9ccdabfd70b33";

    int passed = (err == ERROR_NONE) && strcmp(auth.value, expected_signature) == 0;
    if (!passed) {
        printf("Expected:\n%s\nGot:\n%s\n", expected_signature, auth.value);
    }
    print_test_result("test_sigv4_static_values", passed, err);
    return !passed;
}

// === Test Runner ===

TestCase test_cases[] = {
    {"test_sigv4_static_values", test_sigv4_static_values},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
