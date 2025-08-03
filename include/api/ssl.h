// api/ssl.h

#ifndef SSL_HELPER_H
#define SSL_HELPER_H

#include <openssl/ssl.h>
#include "error.h"

/**
 * @brief Creates and configures an SSL_CTX for TLS server mode.
 *
 * Loads the server certificate, private key, and CA certificate used to verify client certificates.
 * Exits on failure via stderr logging and returns NULL.
 *
 * This version is simpler but does not propagate errors cleanly.
 *
 * @param cert_file Path to the PEM-encoded server certificate.
 * @param key_file  Path to the PEM-encoded private key.
 * @param ca_file   Path to the PEM-encoded CA certificate used for client auth.
 * @return Pointer to a configured SSL_CTX object, or NULL on failure.
 */
SSL_CTX *create_ssl_context(const char *cert_file, const char *key_file, const char *ca_file);

/**
 * @brief Creates an SSL_CTX for TLS server mode with detailed error reporting.
 *
 * This safer alternative to `create_ssl_context()` returns an ErrorCode instead of NULL on failure,
 * and populates the output parameter with a valid SSL_CTX pointer on success.
 *
 * @param cert_file Path to the PEM-encoded server certificate.
 * @param key_file  Path to the PEM-encoded private key.
 * @param ca_file   Path to the PEM-encoded CA certificate used to verify clients.
 * @param out_ctx   Output pointer for the resulting SSL_CTX instance.
 * @return ErrorCode indicating success or a specific failure reason.
 */
ErrorCode create_ssl_context_safe(
    const char *cert_file,
    const char *key_file,
    const char *ca_file,
    SSL_CTX **out_ctx
);

ErrorCode create_psk_context_safe(const char *identity, const char *psk_hex, SSL_CTX **out_ctx);

#endif // SSL_HELPER_H
