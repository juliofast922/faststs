#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include "api/ssl.h"
#include "logger.h"
#include "error.h"
#include "api/clients.h"

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

    // Enforce security settings
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION); // disable compression (CRIME)

    // Cipher preferences (adjust based on performance profile)
    const char *preferred_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_cipher_list(ctx, preferred_ciphers);

    // Session caching
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(ctx, 128);

    // Session ID context for reusability
    unsigned char sid_ctx[] = "fastgate-session-id";
    if (SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1) != 1) {
        log_error("Failed to set session ID context");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Certificates
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

    // Client certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cert_callback);
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        log_error("Failed to load CA certificate from %s", ca_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // --- REGISTER PSK CALLBACK ---
    load_psk_policy_from_env();
    init_psk_identity_index();
    SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

    log_debug("SSL context initialized with cert='%s', key='%s', ca='%s'",
              cert_file, key_file, ca_file);

    return ctx;
}

ErrorCode create_ssl_context_safe(const char *cert_file, const char *key_file, const char *ca_file, SSL_CTX **out_ctx) {
    *out_ctx = create_ssl_context(cert_file, key_file, ca_file);
    return *out_ctx ? ERROR_NONE : ERROR_SSL_HANDSHAKE_FAILED;
}

// --- Buffers para identidad y clave PSK ---
#define MAX_PSK_LEN 64
#define MAX_ID_LEN  128

static unsigned char psk_buf[MAX_PSK_LEN];
static unsigned int psk_buf_len = 0;
static char psk_id_buf[MAX_ID_LEN];

// --- Callback de cliente PSK ---
unsigned int client_psk_cb(SSL *ssl,
                           const char *hint,
                           char *identity,
                           unsigned int max_identity_len,
                           unsigned char *psk,
                           unsigned int max_psk_len) {
    (void)ssl;
    (void)hint;

    strncpy(identity, psk_id_buf, max_identity_len - 1);
    identity[max_identity_len - 1] = '\0';

    if (psk_buf_len > max_psk_len) {
        log_error("PSK buffer too large for server");
        return 0;
    }

    memcpy(psk, psk_buf, psk_buf_len);
    return psk_buf_len;
}

ErrorCode create_psk_context_safe(const char *identity, const char *psk_hex, SSL_CTX **out_ctx) {
    *out_ctx = SSL_CTX_new(TLS_server_method());

    if (!*out_ctx) {
        log_error("Failed to create PSK server context");
        return ERROR_SSL_CTX;
    }
    
    SSL_CTX_set_verify(*out_ctx, SSL_VERIFY_NONE, NULL);

    // Convertir la clave PSK hexadecimal
    size_t len = strlen(psk_hex);
    if (len % 2 != 0 || len / 2 > MAX_PSK_LEN) {
        log_error("Invalid PSK hex length");
        SSL_CTX_free(*out_ctx);
        return ERROR_INVALID_ARGUMENT;
    }

    psk_buf_len = 0;
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte = 0;
        if (sscanf(psk_hex + i, "%2x", &byte) != 1) {
            log_error("Invalid hex at position %zu", i);
            SSL_CTX_free(*out_ctx);
            return ERROR_INVALID_ARGUMENT;
        }
        psk_buf[psk_buf_len++] = (unsigned char)byte;
    }

    strncpy(psk_id_buf, identity, sizeof(psk_id_buf) - 1);
    psk_id_buf[sizeof(psk_id_buf) - 1] = '\0';

    SSL_CTX_set_psk_server_callback(*out_ctx, psk_server_callback);

    return ERROR_NONE;
}