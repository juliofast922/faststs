#ifndef ERROR_H
#define ERROR_H

/**
 * @brief Error codes used across domain deserialization and validation.
 */
typedef enum {
    ERROR_NONE = 0,
    ERROR_DESERIALIZE_MISSING_FIELD,
    ERROR_DESERIALIZE_INVALID_FORMAT,
    ERROR_VALIDATION_FAILED,
    ERROR_CREDENTIALS_NOT_FOUND,
    ERROR_SIGV4_INVALID_INPUT,
    ERROR_SIGV4_SIGNING_FAILURE,
    ERROR_HTTP_INVALID_INPUT,
    ERROR_HTTP_INIT_FAILED,
    ERROR_HTTP_CURL,
    ERROR_UNKNOWN
    // Add more domain-specific errors here
} ErrorCode;

/**
 * @brief Returns a string representation of the error code.
 *
 * @param code ErrorCode enum.
 * @return const char* Description for logging or display.
 */
const char* error_to_string(ErrorCode code);

#endif // ERROR_H
