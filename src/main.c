// src/main.c

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

#include "api/routes/base.h"
#include "api/router.h"
#include "api/ssl.h"
#include "api/transport.h"

int main() {
    SSL_library_init();
    logger_init(".env");
    //logger_set_file_logging(1, 300); <- Set Log file

    log_debug("Starting fastgate API...");

    // Load port from .env or ENV
    int port = 8443; // default fallback
    char port_buf[16];

    if (get_env_from_file(".env", "HTTP_PORT", port_buf, sizeof(port_buf)) ||
        (get_env_str("HTTP_PORT") && strncpy(port_buf, get_env_str("HTTP_PORT"), sizeof(port_buf)))) {
        port_buf[sizeof(port_buf) - 1] = '\0';
        port = atoi(port_buf);
        if (port <= 0 || port > 65535) {
            log_warn("Invalid PORT specified: %s — using default 8443", port_buf);
            port = 8443;
        } else {
            log_debug("Loaded port from env: %d", port);
        }
    }

    SSL_CTX *ctx = NULL;
    ErrorCode err = create_ssl_context_safe("certs/server.crt", "certs/server.key", "certs/ca.crt", &ctx);
    if (err != ERROR_NONE) {
        log_error("Failed to initialize SSL context: %s", error_to_string(err));
        return 1;
    }

    // Register routes
    register_route("GET", "/", handle_root, AUTH_MTLS);
    register_route("GET", "/benchmark", handle_benchmark, AUTH_NONE);

    // Start server
    int server_fd;
    err = http_transport.start(port, &server_fd);
    if (err != ERROR_NONE) {
        log_error("Failed to start server on port %d: %s", port, error_to_string(err));
        SSL_CTX_free(ctx);
        return 1;
    }

    log_info("Server started successfully on port %d", port);

    err = http_transport.accept_loop(ctx);
    if (err != ERROR_NONE) {
        log_error("Server accept loop failed: %s", error_to_string(err));
        if (http_transport.stop) http_transport.stop();
    }

    if (http_transport.stop) http_transport.stop();
    SSL_CTX_free(ctx);
    return 0;
}
