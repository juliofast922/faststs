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
 * @param cert Path to the PEM-encoded server certificate.
 * @param key  Path to the PEM-encoded private key.
 * @param ca   Path to the PEM-encoded CA certificate used for client auth.
 * @return Pointer to a configured SSL_CTX object, or NULL on failure.
 */
SSL_CTX *create_ssl_context(const char *cert, const char *key, const char *ca);

#endif // SSL_HELPER_H
