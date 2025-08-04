#include <stdio.h>
#include <string.h>
#include <time.h>
#include "http.h"
#include "test_utils.h"
#include "logger.h"
#include "error.h"

static long elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000L +
           (end.tv_nsec - start.tv_nsec) / 1000000L;
}

/**
 * @brief Simple GET request to a stable HTTP test service.
 */
int test_http_get_ok(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    HttpRequest req = {
        .url = "https://postman-echo.com/get?foo=bar",
        .method = "GET",
        .headers = (const char*[]) { NULL },
        .body = NULL,
        .body_len = 0,
        .timeout_seconds = 5
    };

    HttpResponse res = {0};
    ErrorCode err = http_execute(&req, &res);

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = elapsed_ms(start, end);

    int passed = err == ERROR_NONE && res.status_code == 200 &&
                 res.body && strstr(res.body, "\"foo\": \"bar\"");

    if (!passed) {
        log_debug("HTTP Response code: %ld\n", res.status_code);
        if (res.body) log_info("HTTP Body:\n%s\n", res.body);
    }

    print_test_result("test_http_get_ok", passed, err);
    log_info("[timing] GET took %ld ms\n", ms);
    http_response_free(&res);
    return passed ? 0 : 1;
}

/**
 * @brief Invalid URL should fail gracefully.
 */
int test_http_invalid_url(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    HttpRequest req = {
        .url = "https://invalid.localhost.test",
        .method = "GET",
        .headers = (const char*[]) { NULL },
        .body = NULL,
        .body_len = 0,
        .timeout_seconds = 3
    };

    HttpResponse res = {0};
    ErrorCode err = http_execute(&req, &res);

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = elapsed_ms(start, end);

    int passed = err == ERROR_HTTP_CURL;
    print_test_result("test_http_invalid_url", passed, err);
    log_info("[timing] INVALID URL took %ld ms\n", ms);
    http_response_free(&res);
    return passed ? 0 : 1;
}

/**
 * @brief POST request with JSON body and custom headers.
 */
int test_http_post_with_body(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    const char *json_body = "{\"message\": \"Hello, world!\"}";

    HttpRequest req = {
        .url = "https://postman-echo.com/post",
        .method = "POST",
        .headers = (const char*[]) {
            "Content-Type: application/json",
            "X-Custom-Header: MyValue",
            NULL
        },
        .body = json_body,
        .body_len = strlen(json_body),
        .timeout_seconds = 5
    };

    HttpResponse res = {0};
    ErrorCode err = http_execute(&req, &res);

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = elapsed_ms(start, end);

    int passed = err == ERROR_NONE &&
                res.status_code == 200 &&
                res.body &&
                strstr(res.body, "\"message\": \"Hello, world!\"") &&
                strstr(res.body, "\"x-custom-header\": \"MyValue\"");

    if (!passed) {
        log_error("HTTP Response code: %ld\n", res.status_code);
        if (res.body) log_error("HTTP Body:\n%s\n", res.body);
    }

    print_test_result("test_http_post_with_body", passed, err);
    log_info("[timing] POST took %ld ms\n", ms);
    http_response_free(&res);
    return passed ? 0 : 1;
}

// === Test Runner ===

TestCase test_cases[] = {
    {"test_http_get_ok", test_http_get_ok},
    {"test_http_invalid_url", test_http_invalid_url},
    {"test_http_post_with_body", test_http_post_with_body},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
