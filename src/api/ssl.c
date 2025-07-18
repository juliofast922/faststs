// api/ssl.c

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

#include "api/ssl.h"
#include "logger.h"
#include "error.h"

SSL_CTX *create_ssl_context(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_CTX *ctx;

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_error("SSL_CTX_new() failed");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load server certificate from %s", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load private key from %s", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify client certificates
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        log_error("Failed to load CA certificate from %s", ca_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    log_info("SSL context initialized with server cert='%s', key='%s', ca='%s'",
             cert_file, key_file, ca_file);

    return ctx;
}

ErrorCode create_ssl_context_safe(const char *cert_file, const char *key_file, const char *ca_file, SSL_CTX **out_ctx) {
    *out_ctx = create_ssl_context(cert_file, key_file, ca_file);
    return *out_ctx ? ERROR_NONE : ERROR_SSL_HANDSHAKE_FAILED;
}
