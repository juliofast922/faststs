#include "aws/aws_error.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

typedef struct {
    AWSError code;
    int http_status;
    const char *aws_type;
    const char *message;
} AWSErrorInfo;

static AWSErrorInfo aws_error_table[] = {
    {AWS_ERROR_INCOMPLETE_SIGNATURE,      400, "IncompleteSignature", "The request signature does not conform to AWS standards."},
    {AWS_ERROR_INTERNAL_FAILURE,          500, "InternalFailure", "The request processing has failed due to an unknown error."},
    {AWS_ERROR_INVALID_ACTION,            400, "InvalidAction", "The action or operation requested is invalid."},
    {AWS_ERROR_INVALID_CLIENT_TOKEN_ID,   403, "InvalidClientTokenId", "The X.509 certificate or AWS Access Key Id provided does not exist."},
    {AWS_ERROR_INVALID_PARAMETER_COMBINATION, 400, "InvalidParameterCombination", "Parameters in the request are inconsistent or incompatible."},
    {AWS_ERROR_INVALID_QUERY_PARAMETER,   400, "InvalidQueryParameter", "A query parameter name is invalid."},
    {AWS_ERROR_INVALID_PARAMETER_VALUE,   400, "InvalidParameterValue", "A parameter has a value that is not valid."},
    {AWS_ERROR_MISSING_ACTION,            400, "MissingAction", "The request is missing an action."},
    {AWS_ERROR_MISSING_AUTHENTICATION_TOKEN, 403, "MissingAuthenticationToken", "The request must contain either a valid (registered) AWS access key ID or X.509 certificate."},
    {AWS_ERROR_REQUEST_EXPIRED,           400, "RequestExpired", "Request expired."},
    {AWS_ERROR_SIGNATURE_DOES_NOT_MATCH,  403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided."},
    {AWS_ERROR_ACCESS_DENIED,             403, "AccessDenied", "Access denied."},
    {AWS_ERROR_UNKNOWN,                   500, "UnknownError", "An unknown error occurred."}
};

int aws_error_to_http_status(AWSError error) {
    for (size_t i = 0; i < sizeof(aws_error_table) / sizeof(aws_error_table[0]); i++) {
        if (aws_error_table[i].code == error)
            return aws_error_table[i].http_status;
    }
    return 500;
}

AWSError aws_error_from_code(const char *code_str) {
    if (!code_str) return AWS_ERROR_UNKNOWN;

    for (size_t i = 0; i < sizeof(aws_error_table) / sizeof(aws_error_table[0]); i++) {
        if (strcmp(aws_error_table[i].aws_type, code_str) == 0) {
            return aws_error_table[i].code;
        }
    }

    return AWS_ERROR_UNKNOWN;
}

void respond_with_aws_error(SSL *ssl, AWSError error, const char *custom_message) {
    const AWSErrorInfo *info = NULL;

    for (size_t i = 0; i < sizeof(aws_error_table) / sizeof(aws_error_table[0]); i++) {
        if (aws_error_table[i].code == error) {
            info = &aws_error_table[i];
            break;
        }
    }

    if (!info) return;

    // === Generate pseudo RequestId ===
    const char *request_id = generate_request_id();

    // === Determine final message ===
    const char *message = custom_message ? custom_message : info->message;

    // === Build XML body ===
    char body[1024];
    snprintf(body, sizeof(body),
        "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\n"
        "  <Error>\n"
        "    <Type>%s</Type>\n"
        "    <Code>%s</Code>\n"
        "    <Message>%s</Message>\n"
        "  </Error>\n"
        "  <RequestId>%s</RequestId>\n"
        "</ErrorResponse>\n",
        info->http_status >= 500 ? "Receiver" : "Sender",
        info->aws_type,
        message,
        request_id
    );

    // === Compose full HTTP response ===
    char response[1600];
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/xml\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        info->http_status, info->aws_type, strlen(body), body);

    SSL_write(ssl, response, strlen(response));
}