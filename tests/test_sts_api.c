#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "api/transport.h"
#include "aws/request.h"
#include "api/ssl.h"
#include "api/router.h"
#include "http.h"
#include "utils.h"
#include "logger.h"
#include "aws/credentials.h"
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

    AwsSignedRequest aws_req = {
        .url = "https://sts.amazonaws.com/",
        .method = "POST",
        .service = "sts",
        .region = "us-east-1",
        .body = "Action=GetCallerIdentity&Version=2011-06-15",
        .signed_headers = "content-type;host;x-amz-date",
        .timeout_seconds = 5
    };

    HttpResponse res = {0};
    err = aws_signed_request_execute(&aws_req, &res);

    http_transport.stop();
    pthread_join(server_thread, NULL);
    SSL_CTX_free(ctx);

    int passed = err == ERROR_NONE && (
        (res.status_code == 200) ||
        (res.status_code == 403 && res.body && strstr(res.body, "<Code>InvalidClientTokenId</Code>"))
    );
    if (!passed) {
        log_error("Unexpected failure");
        log_error("HTTP Status: %ld", res.status_code);
        if (res.body) log_error("Body: %s", res.body);
    }

    log_debug("Response Body: %s", res.body);

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