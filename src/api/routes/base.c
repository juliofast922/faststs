// api/routes/base.c

#include "api/routes/base.h"
#include <string.h>

void handle_root(SSL *ssl, const char *request) {
    (void)request;
    const char *body = "Hello, World!\n";
    char response[256];

    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        strlen(body), body);

    SSL_write(ssl, response, strlen(response));
}

void handle_benchmark(SSL *ssl, const char *request) {
    (void)request;
    const char *body = "Benchmark OK\n";
    char response[256];

    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        strlen(body), body);

    SSL_write(ssl, response, strlen(response));
}
