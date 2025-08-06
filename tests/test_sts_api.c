#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "api/transport.h"
#include "api/ssl.h"
#include "api/router.h"
#include "http.h"
#include "utils.h"
#include "logger.h"
#include "aws/credentials.h"
#include "aws/sigv4.h"
#include "aws/canonical_request.h"
#include "api/routes/sts_dispatcher.h"
#include "test_utils.h"

static const int port = 9555;

void* server_thread_func(void *arg) {
    SSL_CTX *ctx = (SSL_CTX *)arg;
    http_transport.accept_loop(ctx);
    return NULL;
}

int test_sigv4_get_caller_identity(void) {
    if (!load_env_file(".env")) {
        log_warn("Could not load .env file — relying on existing environment variables");
    }

    // Setup SSL context
    ErrorCode err;
    SSL_CTX *ctx = create_ssl_context("certs/server.crt", "certs/server.key", "certs/ca.crt");
    if (!ctx) {
        print_test_result("test_sigv4_get_caller_identity", 0, ERROR_SSL_CONTEXT_INIT);
        return 1;
    }

    // Register route with no auth for testing
    register_route("POST", "/sts", handle_sts_dispatcher, AUTH_NONE);

    // Start server thread
    pthread_t server_thread;
    http_transport.start(port, NULL);
    pthread_create(&server_thread, NULL, server_thread_func, ctx);
    sleep(1);

    // Load credentials
    AwsCredentials creds;
    err = load_credentials(&creds);
    if (err != ERROR_NONE) {
        print_test_result("test_sigv4_get_caller_identity", 0, err);
        return 1;
    }

    // Generate timestamps
    char iso_time[32];
    char amz_date[17];
    char short_date[9];

    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%SZ", &tm);
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);
    strftime(short_date, sizeof(short_date), "%Y%m%d", &tm);

    // === Construct the body ===
    char request_body[1024];
    snprintf(request_body, sizeof(request_body),
        "Action=GetCallerIdentity"
        "&Version=2011-06-15"
        "&Timestamp=%s"
        "&AWSAccessKeyId=%s",
        iso_time,
        creds.access_key
    );
    request_body[sizeof(request_body) - 1] = '\0';

    // Compute hash of body
    char payload_hash[65];
    sha256_hex(request_body, payload_hash);

    // Create headers string for canonical request
    char headers_buf[128];
    snprintf(headers_buf, sizeof(headers_buf), "host:localhost\nx-amz-date:%s\n", amz_date);

    // Create canonical request
    CanonicalRequest cr = {
        .method = "POST",
        .uri = "/sts",
        .query_string = "",
        .headers = headers_buf,
        .signed_headers = "host;x-amz-date",
        .payload_hash = payload_hash
    };

    char canonical_buf[1024];
    err = canonical_request_build(&cr, canonical_buf, sizeof(canonical_buf));
    if (err != ERROR_NONE) {
        print_test_result("test_sigv4_get_caller_identity", 0, err);
        return 1;
    }

    // Build authorization header
    AuthorizationHeader auth_hdr = {0};
    err = authorization_header_build(
        &creds,
        amz_date,
        short_date,
        "us-east-1",
        "sts",
        canonical_buf,
        &auth_hdr
    );
    log_debug("Computed signature: %s", auth_hdr.signature);
    if (err != ERROR_NONE) {
        print_test_result("test_sigv4_get_caller_identity", 0, err);
        return 1;
    }

    // Prepare HTTP headers
    char x_amz_date_header[64];
    snprintf(x_amz_date_header, sizeof(x_amz_date_header), "X-Amz-Date: %s", amz_date);

    char auth_header_full[1056];
    snprintf(auth_header_full, sizeof(auth_header_full), "Authorization: %s", auth_hdr.value);

    const char *headers[] = {
        "Content-Type: application/x-www-form-urlencoded",
        x_amz_date_header,
        auth_header_full,
        NULL
    };

    log_debug("Final request body: %s", request_body);

    // Execute HTTP request
    HttpRequest req = {
        .url = "https://localhost:9555/sts",
        .method = "POST",
        .headers = headers,
        .body = request_body,
        .body_len = strlen(request_body),
        .timeout_seconds = 5,
    };

    HttpResponse res = {0};
    err = http_execute(&req, &res);

    http_transport.stop();
    pthread_join(server_thread, NULL);
    SSL_CTX_free(ctx);

    int passed = err == ERROR_NONE && res.status_code == 200;
    if (!passed) {
        log_error("HTTP Status: %ld", res.status_code);
        if (res.body) log_error("Body: %s", res.body);
    }

    print_test_result("test_sigv4_get_caller_identity", passed, err);
    http_response_free(&res);
    return passed ? 0 : 1;
}

TestCase test_cases[] = {
    {"test_sigv4_get_caller_identity", test_sigv4_get_caller_identity},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}