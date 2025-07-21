#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <stdatomic.h>

#include "error.h"
#include "logger.h"
#include "api/transport.h"
#include "api/ssl.h"
#include "api/router.h"

#define MAX_CLIENTS 10
#define READ_BUF_SIZE 4096
#define READ_TIMEOUT_SEC 15

// Static file descriptor shared between start() and accept_loop()
static int server_fd = -1;

static atomic_int should_stop = 0;

ErrorCode http_transport_stop(void) {
    atomic_store(&should_stop, 1);

    if (server_fd >= 0) {
        shutdown(server_fd, SHUT_RDWR);  // unblock accept()
        close(server_fd);
        server_fd = -1;
        return ERROR_NONE;
    }

    return ERROR_SOCKET_ALREADY_CLOSED;
}

static ErrorCode create_server_socket(int port, int *out_fd) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("socket() failed");
        return ERROR_SOCKET_CREATE_FAILED;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("bind() failed");
        close(sockfd);
        return ERROR_SOCKET_BIND_FAILED;
    }

    if (listen(sockfd, MAX_CLIENTS) < 0) {
        log_error("listen() failed");
        close(sockfd);
        return ERROR_SOCKET_LISTEN_FAILED;
    }

    *out_fd = sockfd;
    return ERROR_NONE;
}

static ErrorCode http_start(int port, int *out_fd) {
    ErrorCode err = create_server_socket(port, &server_fd);
    if (err == ERROR_NONE && out_fd) {
        *out_fd = server_fd;
    }
    return err;
}

static ErrorCode http_accept_loop(SSL_CTX *ctx) {
    if (server_fd < 0) {
        log_error("accept_loop called before start()");
        return ERROR_SOCKET_ACCEPT_FAILED;
    }

    log_debug("Accept loop starting...");

    while (!atomic_load(&should_stop)) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        
        int client_fd = accept(server_fd, (struct sockaddr*)&addr, &len);
        if (client_fd < 0) {
            if (atomic_load(&should_stop)) break;  // likely interrupted by shutdown
            log_warn("accept() failed");
            continue;
        }

        struct timeval timeout = {
            .tv_sec = READ_TIMEOUT_SEC,
            .tv_usec = 0
        };
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            log_warn("Failed to set socket read timeout");
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            log_error("SSL_new() failed");
            close(client_fd);
            continue;
        }

        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            log_error("SSL_accept() failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        char buf[READ_BUF_SIZE];
        int keep_alive = 1;

        while (keep_alive) {
            memset(buf, 0, sizeof(buf));

            int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (bytes <= 0) {
                int err = SSL_get_error(ssl, bytes);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    log_debug("SSL connection closed by peer");
                } else {
                    log_error("SSL_read() failed");
                    ERR_print_errors_fp(stderr);
                }
                break;
            }

            buf[bytes] = '\0';
            log_debug("Received request:\n%s", buf);

            // Detectar Connection: close para terminar
            if (strstr(buf, "Connection: close") || strstr(buf, "connection: close")) {
                keep_alive = 0;
            }

            handle_request(ssl, buf);
        }

        // Cerrar conexión TLS después del loop
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }

    log_debug("Shutting down accept loop");
    atomic_store(&should_stop, 0);
    return ERROR_NONE;
}

Transport http_transport = {
    .start = http_start,
    .accept_loop = http_accept_loop,
    .stop = http_transport_stop
};
