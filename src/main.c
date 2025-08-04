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

#include "api/routes/sts_dispatcher.h"

#include <sys/resource.h>
#include <signal.h>

void bump_fd_limit() {
    struct rlimit lim = {10000, 10000};
    setrlimit(RLIMIT_NOFILE, &lim);
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    bump_fd_limit();
    SSL_library_init();

    // Load environment variables from .env (if present)
    if (!load_env_file(".env")) {
        log_warn("Could not load .env file — relying on existing environment variables");
    }

    logger_init(".env");
    //logger_set_file_logging(1, 300); <- Set Log file

    
    log_debug("Starting fastgate API...");

    // Load port from environment (with fallback)
    int port = 8443; // default fallback
    const char *port_str = get_env_str("HTTP_PORT");

    if (port_str) {
        port = atoi(port_str);
        if (port <= 0 || port > 65535) {
            log_warn("Invalid PORT specified: %s — using default 8443", port_str);
            port = 8443;
        } else {
            log_debug("Loaded port from environment: %d", port);
        }
    }

    SSL_CTX *ctx = NULL;
    ErrorCode err = create_ssl_context_safe("certs/server.crt", "certs/server.key", "certs/ca.crt", &ctx);
    if (err != ERROR_NONE) {
        log_error("Failed to initialize SSL context: %s", error_to_string(err));
        return 1;
    }

    // Register routes
    register_route("GET", "/", handle_root, AUTH_NONE);
    register_route("GET", "/mtls", handle_root, AUTH_MTLS);
    register_route("GET", "/psk", handle_root, AUTH_PSK);
    register_route("POST", "/sts", handle_sts_dispatcher, AUTH_MTLS);

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
