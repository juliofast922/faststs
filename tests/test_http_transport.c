#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include "api/transport.h"
#include "api/ssl.h"
#include "api/router.h"
#include "api/handlers.h"
#include "http.h"
#include "error.h"
#include "test_utils.h"

// === SERVER THREAD ===

typedef struct {
    SSL_CTX *ctx;
    int port;
} ServerArgs;

void* server_thread_func(void *arg) {
    ServerArgs *args = (ServerArgs*)arg;
    http_transport.accept_loop(args->ctx);
    return NULL;
}

// === TEST ===

int test_tls_hello_world(void) {
    const int port = 9443;

    // Setup TLS context
    SSL_CTX *ctx = NULL;
    ErrorCode err = create_ssl_context_safe(
        "certs/server.crt",
        "certs/server.key",
        "certs/ca.crt",
        &ctx
    );
    if (err != ERROR_NONE || !ctx) {
        print_test_result("test_tls_hello_world", 0, err);
        return 1;
    }

    // Register test handler
    register_route("GET", "/", handle_root, AUTH_MTLS);

    // Start server in background thread
    pthread_t server_thread;
    ServerArgs args = { .ctx = ctx, .port = port };
    http_transport.start(port, NULL);
    pthread_create(&server_thread, NULL, server_thread_func, &args);

    // Wait a moment for server to be ready
    sleep(1);

    // === Make HTTPS request with client certificate ===
    HttpRequest req = {
        .url = "https://localhost:9443/",
        .method = "GET",
        .headers = (const char*[]){ NULL },
        .body = NULL,
        .body_len = 0,
        .timeout_seconds = 3,
        .cert_path = "certs/client.crt",
        .key_path  = "certs/client.key",
        .ca_path   = "certs/ca.crt"
    };

    HttpResponse res = {0};
    err = http_execute(&req, &res);

    // === Cleanup ===
    extern ErrorCode http_transport_stop(void);
    http_transport_stop();  // ✅ <--- This was missing
    pthread_join(server_thread, NULL);
    SSL_CTX_free(ctx);

    int passed = err == ERROR_NONE &&
             res.status_code == 200 &&
             res.body &&
             strstr(res.body, "Hello, World!");

    print_test_result("test_tls_hello_world", passed, err);
    http_response_free(&res);
    return passed ? 0 : 1;
}

// === Test Runner ===

TestCase test_cases[] = {
    {"test_tls_hello_world", test_tls_hello_world},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
