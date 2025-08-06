#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include "api/ssl.h"
#include "logger.h"
#include "error.h"
#include "api/clients.h"

SSL_CTX *create_ssl_context(const char *cert, const char *key, const char *ca)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_error("SSL_CTX_new failed");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);

    const char *preferred_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_cipher_list(ctx, preferred_ciphers);

    unsigned char sid_ctx[] = "fastgate-session-id";
    SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1);

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load cert/key");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (ca && SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        log_warn("CA file not loaded: %s", ca);
    }

    // mTLS: Accept any cert, validate later
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cert_callback);

    // PSK support
    load_psk_policy_from_env();
    init_psk_identity_index();
    SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

    log_info("SSL context initialized (cert=%s)", cert);
    return ctx;
}