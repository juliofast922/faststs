// api/router.h

#ifndef ROUTER_H
#define ROUTER_H

#include <openssl/ssl.h>

#define SSL_EX_AUTHORIZED_IDX 1

typedef enum {
    AUTH_NONE,
    AUTH_MTLS
    // AUTH_API_KEY, AUTH_JWT, etc.
} AuthPolicy;

/**
 * @brief Type definition for HTTP route handler functions.
 *
 * Each route handler receives the active SSL connection and the raw HTTP request string.
 */
typedef void (*route_handler_t)(SSL *ssl, const char *request);

/**
 * @brief Registers a route and its associated handler.
 *
 * Adds a new route (method + path) to the routing table. If the maximum number of
 * routes is reached, registration will fail silently.
 *
 * @param method  The HTTP method (e.g., "GET", "POST").
 * @param path    The URL path (e.g., "/", "/login").
 * @param handler The function to handle this route.
 * @param auth    Auth Policy to specific endpoint
 */
void register_route(const char *method, const char *path, route_handler_t handler, AuthPolicy auth);

/**
 * @brief Dispatches an incoming request to the appropriate route handler.
 *
 * Parses the method and path from the raw HTTP request, verifies client certificate,
 * matches the request against the registered routes, and invokes the handler if matched.
 * Sends a 400, 403, or 404 HTTP response for malformed, unauthorized, or unmatched requests.
 *
 * @param ssl         The active SSL connection with the client.
 * @param raw_request The raw HTTP request string as received over the connection.
 */
void handle_request(SSL *ssl, const char *raw_request);

#endif // ROUTER_H
