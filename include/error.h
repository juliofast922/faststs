#ifndef ERROR_H
#define ERROR_H

/**
 * @brief Error codes used across domain deserialization and validation.
 */
typedef enum {
    // Generic success
    ERROR_NONE = 0,

    // Deserialization / parsing
    ERROR_DESERIALIZE_MISSING_FIELD,
    ERROR_DESERIALIZE_INVALID_FORMAT,

    // Validation
    ERROR_VALIDATION_FAILED,

    // AWS credentials
    ERROR_CREDENTIALS_NOT_FOUND,

    // SigV4
    ERROR_SIGV4_INVALID_INPUT,
    ERROR_SIGV4_SIGNING_FAILURE,
    ERROR_INVALID_CLIENT_TOKEN_ID,
    ERROR_SIGV4_INVALID_FORMAT,
    

    // HTTP client
    ERROR_HTTP_INVALID_INPUT,
    ERROR_HTTP_INIT_FAILED,
    ERROR_HTTP_CURL,

    // HTTP server / transport
    ERROR_SOCKET_CREATE_FAILED,
    ERROR_SOCKET_BIND_FAILED,
    ERROR_SOCKET_LISTEN_FAILED,
    ERROR_SOCKET_ACCEPT_FAILED,
    ERROR_SSL_HANDSHAKE_FAILED,
    ERROR_SSL_READ_FAILED,
    ERROR_SSL_WRITE_FAILED,
    ERROR_SOCKET_ALREADY_CLOSED,

    ERROR_SSL_CONTEXT_INIT,
    ERROR_SSL_CERTIFICATE_LOAD,

    // PSK-related
    ERROR_SSL_CTX,
    ERROR_INVALID_ARGUMENT,

    // Fallback
    ERROR_MEMORY_ALLOCATION,
    ERROR_UNKNOWN
} ErrorCode;

/**
 * @brief Returns a string representation of the error code.
 *
 * @param code ErrorCode enum.
 * @return const char* Description for logging or display.
 */
const char* error_to_string(ErrorCode code);

#endif // ERROR_H
