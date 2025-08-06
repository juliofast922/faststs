// include/aws/error.h

#ifndef AWS_ERROR_H
#define AWS_ERROR_H

#include <openssl/ssl.h>

typedef enum {
    AWS_ERROR_NONE = 0,
    AWS_ERROR_INCOMPLETE_SIGNATURE,
    AWS_ERROR_INTERNAL_FAILURE,
    AWS_ERROR_INVALID_ACTION,
    AWS_ERROR_INVALID_CLIENT_TOKEN_ID,
    AWS_ERROR_INVALID_PARAMETER_COMBINATION,
    AWS_ERROR_INVALID_QUERY_PARAMETER,
    AWS_ERROR_INVALID_PARAMETER_VALUE,
    AWS_ERROR_MISSING_ACTION,
    AWS_ERROR_MISSING_AUTHENTICATION_TOKEN,
    AWS_ERROR_REQUEST_EXPIRED,
    AWS_ERROR_SIGNATURE_DOES_NOT_MATCH,
    AWS_ERROR_ACCESS_DENIED,
    AWS_ERROR_UNKNOWN
} AWSError;

/**
 * Converts an AWSError enum to a corresponding HTTP status code.
 */
int aws_error_to_http_status(AWSError error);

/**
 * Maps an AWS <Code> string to the corresponding AWSError enum.
 */
AWSError aws_error_from_code(const char *code_str);

/**
 * Writes an AWS-style JSON error response to the SSL socket.
 */
void respond_with_aws_error(SSL *ssl, AWSError error, const char *custom_message);

#endif // AWS_ERROR_H