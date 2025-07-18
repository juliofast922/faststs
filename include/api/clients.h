// api/auth.h

#ifndef CLIENTS_H
#define CLIENTS_H

#include <openssl/x509.h>
#include "error.h"

/**
 * @brief Verifies if a client certificate matches a known subject.
 *
 * @param client_cert Pointer to the client's X509 certificate.
 * @return ERROR_NONE if allowed, specific ErrorCode otherwise.
 */
ErrorCode is_client_allowed(X509 *client_cert);

#endif // CLIENTS_H
