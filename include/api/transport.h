// api/transport.h

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <openssl/ssl.h>
#include "error.h"

/**
 * @brief Transport interface for server communication layers (HTTP, RPC, etc).
 *
 * This abstraction allows you to switch between HTTP and other protocols (e.g., RPC)
 * without modifying core routing or SSL logic. Each transport defines how to start
 * listening and how to accept incoming secure connections.
 */
typedef struct {
    /**
     * @brief Initializes the transport by binding to the given port and preparing for incoming connections.
     *
     * @param port        The TCP port to bind to (e.g., 443, 8443).
     * @param out_sockfd  Output parameter for the created socket descriptor.
     * @return ErrorCode  ERROR_NONE on success, or appropriate error if setup fails.
     */
    ErrorCode (*start)(int port, int *out_sockfd);

    /**
     * @brief Starts the secure connection handling loop for incoming clients.
     *
     * Blocks while accepting new TLS connections using the given SSL context.
     * For each connection, reads the request, verifies the certificate, and dispatches to handlers.
     *
     * @param ctx         Initialized SSL_CTX with proper certs and verification settings.
     * @return ErrorCode  ERROR_NONE on clean shutdown, or error if the accept loop fails.
     */
    ErrorCode (*accept_loop)(SSL_CTX *ctx);

    /**
     * @brief Signals the accept loop to stop after current request (used for test cleanup).
     *
     * @return ErrorCode  ERROR_NONE on clean shutdown.
     * Should be safe to call from another thread.
     */
    ErrorCode (*stop)(void);
} Transport;

/**
 * @brief Global instance for HTTP transport over TLS.
 */
extern Transport http_transport;

/**
 * @brief Placeholder for future RPC transport implementation.
 */
extern Transport rpc_transport;

#endif // TRANSPORT_H
