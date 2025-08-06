#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include "api/transport.h"
#include "api/ssl.h"
#include "api/router.h"
#include "api/routes/base.h"
#include "api/clients.h"
#include "http.h"
#include "error.h"
#include "logger.h"
#include "utils.h"
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
    if (!load_env_file(".env")) {
        log_warn("Could not load .env file — relying on existing environment variables");
    }
    
    const int port = 9443;

    // Setup TLS context
    SSL_CTX *ctx = create_ssl_context(
        "certs/server.crt",
        "certs/server.key",
        "certs/ca.crt"
    );
    if (!ctx) {
        print_test_result("test_tls_hello_world", 0, ERROR_SSL_CONTEXT_INIT);
        return 1;
    }

    ErrorCode err;

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
    http_transport.stop();
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

int test_psk_hello_world(void) {
    if (!load_env_file(".env")) {
        log_warn("Could not load .env file — relying on existing environment variables");
    }
    load_psk_policy_from_env();

    const int port = 9444;

    // Setup PSK context
    SSL_CTX *ctx = create_ssl_context(
        "certs/server.crt",
        "certs/server.key",
        "certs/ca.crt"
    );
    if (!ctx) {
        print_test_result("test_psk_hello_world", 0, ERROR_SSL_CONTEXT_INIT);
        return 1;
    }

    // Register route
    register_route("GET", "/psk", handle_root, AUTH_PSK);

    // Start server
    pthread_t server_thread;
    ServerArgs args = { .ctx = ctx, .port = port };
    http_transport.start(port, NULL);
    pthread_create(&server_thread, NULL, server_thread_func, &args);
    sleep(1);

    FILE *fp = popen(
        "printf 'GET /psk HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | "
        "/usr/bin/openssl s_client -psk_identity client-x -psk 68656c6c6f736563726574 "
        "-connect localhost:9444 -servername localhost -quiet",
        "r");
    
    if (!fp) {
        log_error("Failed to spawn openssl s_client");
        http_transport.stop();
        pthread_join(server_thread, NULL);
        SSL_CTX_free(ctx);
        print_test_result("test_psk_hello_world", 0, ERROR_HTTP_INIT_FAILED);
        return 1;
    }
    
    const char *req = "GET /psk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    fwrite(req, 1, strlen(req), fp);
    fflush(fp);
    
    char buf[4096] = {0};
    fread(buf, 1, sizeof(buf) - 1, fp);
    pclose(fp);

    // Cleanup
    http_transport.stop();
    pthread_join(server_thread, NULL);
    SSL_CTX_free(ctx);

    int passed = strstr(buf, "HTTP/1.1 200 OK") && strstr(buf, "Hello, World!");
    print_test_result("test_psk_hello_world", passed, ERROR_NONE);
    return passed ? 0 : 1;
}

// === Test Runner ===

TestCase test_cases[] = {
    {"test_tls_hello_world", test_tls_hello_world},
    {"test_psk_hello_world", test_psk_hello_world},
    {NULL, NULL}
};

int main(int argc, char *argv[]) {
    return run_all_tests(argc, argv, test_cases);
}
