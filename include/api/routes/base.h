// api/routes/base.h

#ifndef BASE_H
#define BASE_H

#include <openssl/ssl.h>

/**
 * @brief Handles the GET / root endpoint.
 *
 * This function is responsible for processing requests to the base path `/`.
 * It sends a simple HTTP 200 OK response over the given SSL connection.
 *
 * @param ssl     The active SSL connection with the client.
 * @param request The raw HTTP request string (not parsed).
 */
void handle_root(SSL *ssl, const char *request);

#endif // BASE_H
