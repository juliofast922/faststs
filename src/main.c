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

    // Load environment variables from .env (if available)
    if (!load_env_file(".env")) {
        log_warn("Could not load .env file — relying on existing environment variables");
    }

    logger_init();
    // logger_set_file_logging(1, 300); // Optional: enable file logging

    log_debug("Starting fastgate API...");

    // Load port from environment (default fallback: 8443)
    int port = 8443;
    const char *port_str = get_env_str("HTTP_PORT");

    if (port_str) {
        int env_port = atoi(port_str);
        if (env_port > 0 && env_port <= 65535) {
            port = env_port;
            log_debug("Loaded port from environment: %d", port);
        } else {
            log_warn("Invalid HTTP_PORT value: %s — using default 8443", port_str);
        }
    }

    SSL_CTX *ctx = create_ssl_context(
        "certs/server.crt",
        "certs/server.key",
        "certs/ca.crt"
    );

    if (!ctx) {
        log_error("Failed to initialize SSL context");
        return 1;
    }

    // Register API routes
    register_route("GET",  "/benchmark", handle_root,         AUTH_NONE);
    register_route("GET",  "/mtls",      handle_root,         AUTH_MTLS);
    register_route("GET",  "/psk",       handle_root,         AUTH_PSK);
    register_route("POST", "/sts",       handle_sts_dispatcher, AUTH_MTLS);

    // Start server transport
    int server_fd;
    http_transport.start(port, &server_fd);

    log_info("Server started successfully on port %d", port);

    http_transport.accept_loop(ctx);

    if (http_transport.stop) {
        http_transport.stop();
    }

    SSL_CTX_free(ctx);
    return 0;
}
