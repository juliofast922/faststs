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
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

    unsigned char sid_ctx[] = "fastgate-session-id";
    if (SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1) != 1) {
        log_error("Failed to set session ID context");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

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
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        log_error("Failed to load CA certificate from %s", ca_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    log_debug("SSL context initialized with server cert='%s', key='%s', ca='%s'",
             cert_file, key_file, ca_file);

    return ctx;
}

ErrorCode create_ssl_context_safe(const char *cert_file, const char *key_file, const char *ca_file, SSL_CTX **out_ctx) {
    *out_ctx = create_ssl_context(cert_file, key_file, ca_file);
    return *out_ctx ? ERROR_NONE : ERROR_SSL_HANDSHAKE_FAILED;
}
