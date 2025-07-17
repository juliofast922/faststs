#include <stdio.h>
#include <string.h>
#include <time.h>

#include "logger.h"
#include "error.h"
#include "utils.h"
#include "test_utils.h"
#include "http.h"

#include "types/arn.h"

#include "models/user.h"
#include "models/model.h"
#include "models/get_caller_identity.h"

#include "aws/credentials.h"
#include "aws/sigv4.h"
#include "aws/canonical_request.h"

int main(void) {
    log_info("Calling GetCallerIdentity");

    AwsCredentials creds = {0};
    if (load_credentials(&creds, ".env") != ERROR_NONE) {
        log_error("Failed to load AWS credentials");
        return 1;
    }

    // === Step 1: Timestamp ===
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);

    char amz_date[17];  // "YYYYMMDDTHHMMSSZ"
    char date[9];       // "YYYYMMDD"
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", gmt);
    strftime(date, sizeof(date), "%Y%m%d", gmt);

    const char *region = "us-east-1";
    const char *service = "sts";

    // === Step 2: Compute payload hash ===
    const char *body = "Action=GetCallerIdentity&Version=2011-06-15";
    char payload_hash[65];
    sha256_hex(body, payload_hash);
    log_debug("Payload hash: %s", payload_hash);

    // === Step 3: Build Canonical Request ===
    char headers_buf[256];
    snprintf(headers_buf, sizeof(headers_buf), "host:sts.amazonaws.com\nx-amz-date:%s\n", amz_date);

    CanonicalRequest cr = {
        .method = "POST",
        .uri = "/",
        .query_string = "",
        .headers = headers_buf,
        .signed_headers = "host;x-amz-date",
        .payload_hash = payload_hash
    };

    char canonical_request[1024];
    ErrorCode err = canonical_request_build(&cr, canonical_request, sizeof(canonical_request));
    if (err != ERROR_NONE) {
        log_error("Failed to build canonical request: %s", error_to_string(err));
        return 1;
    }

    log_debug("Canonical Request:\n---\n%s\n---", canonical_request);

    // === Step 4: Sign the request ===
    AuthorizationHeader auth = {0};
    err = authorization_header_build(
        &creds, amz_date, date, region, service,
        canonical_request, &auth
    );
    if (err != ERROR_NONE) {
        log_error("Signing failed: %s", error_to_string(err));
        return 1;
    }

    log_debug("Authorization header: %s", auth.value);

    // === Step 5: Build Headers ===
    char auth_header[1100];
    int written = snprintf(auth_header, sizeof(auth_header), "Authorization: %s", auth.value);
    if (written < 0 || written >= (int)sizeof(auth_header)) {
        log_error("Authorization header too long");
        return 1;
    }

    char amz_date_header[64];
    snprintf(amz_date_header, sizeof(amz_date_header), "x-amz-date: %s", amz_date);

    const char *headers[] = {
        "Content-Type: application/x-www-form-urlencoded",
        amz_date_header,
        auth_header,
        NULL
    };

    // === Step 6: Make the HTTP Request ===
    HttpRequest req = {
        .url = "https://sts.amazonaws.com/",
        .method = "POST",
        .headers = headers,
        .body = body,
        .body_len = strlen(body),
        .timeout_seconds = 5
    };

    HttpResponse res = {0};
    err = http_execute(&req, &res);

    if (err != ERROR_NONE || res.status_code != 200) {
        log_error("HTTP error: %s (code: %ld)", error_to_string(err), res.status_code);
        if (res.body) log_debug("Response:\n%s", res.body);
        http_response_free(&res);
        return 1;
    }

    // === Step 7: Deserialize the Response ===
    GetCallerIdentity identity = get_caller_identity_create();
    err = identity.vtable->deserialize_xml(&identity, res.body);
    if (err != ERROR_NONE) {
        log_error("Failed to parse response: %s", error_to_string(err));
    } else {
        log_info("UserId:  %s", identity.user_id);
        log_info("Account: %s", identity.account);
        log_info("ARN:     %s", identity.arn.value);
    }

    http_response_free(&res);
    return err == ERROR_NONE ? 0 : 1;
}
