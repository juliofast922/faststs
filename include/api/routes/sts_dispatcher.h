// include/api/routes/sts_dispatcher.h

#ifndef API_ROUTES_STS_DISPATCHER_H
#define API_ROUTES_STS_DISPATCHER_H

#include <openssl/ssl.h>

/**
 * @brief Dispatcher handler for AWS STS-compatible requests.
 *
 * Matches incoming requests by HTTP method, validates STS `Version`,
 * and dispatches based on `Action` parameter from the request body.
 * 
 * Supported actions:
 *   - GetCallerIdentity
 * 
 * Responds with appropriate AWS-style errors when invalid.
 * Only POST is currently supported, but structure is extensible.
 * 
 * @param ssl The SSL connection.
 * @param request The raw HTTP request string.
 */
void handle_sts_dispatcher(SSL *ssl, const char *request);

#endif // API_ROUTES_STS_DISPATCHER_H
