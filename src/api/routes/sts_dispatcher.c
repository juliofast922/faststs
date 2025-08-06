#include "api/routes/sts_dispatcher.h"
#include "aws/aws_error.h"
#include "models/common_params.h"
#include "aws/sigv4.h"
#include "utils.h"
#include "error.h"
#include "logger.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PARAM_LEN 128

int validate_query_signature(const char *body, const AWSCommonParams *params) {
    if (!body || !params) return 0;

    AwsCredentials creds;
    ErrorCode err = load_credentials(&creds);
    if (err != ERROR_NONE) return 0;

    if (strcmp(creds.access_key, params->access_key_id) != 0) {
        log_warn("Access key ID does not match loaded credentials");
        return 0;
    }

    if (strcmp(params->signature_method, "HmacSHA256") != 0) {
        log_warn("Unsupported signature method: %s", params->signature_method);
        return 0;
    }

    // The string to sign for query-style is just the raw request body (sorted params recommended but optional for now)
    // If you want stricter matching, canonicalize it like AWS would.

    unsigned char hmac_bin[SHA256_DIGEST_LENGTH];
    hmac_sha256((const unsigned char *)creds.secret_key, strlen(creds.secret_key), body, hmac_bin);

    char hmac_hex[65];
    bytes_to_hex(hmac_bin, SHA256_DIGEST_LENGTH, hmac_hex);

    log_debug("Expected signature: %s", params->signature);
    log_debug("Computed signature: %s", hmac_hex);

    return strcasecmp(params->signature, hmac_hex) == 0;
}

void handle_sts_dispatcher(SSL *ssl, const char *request) {
    // Step 1: Extract request body
    const char *body = strstr(request, "\r\n\r\n");
    if (!body || *(body + 4) == '\0') {
        log_warn("Empty or missing body in request");
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE);
        return;
    }
    body += 4;

    // Step 2: Parse and validate parameters
    AWSCommonParams params;
    if (!parse_common_params(body, &params)) {
        log_warn("Failed to parse common parameters");
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE);
        return;
    }

    if (!validate_common_params(&params)) {
        log_warn("Validation failed for parameters");
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE);
        return;
    }

    log_debug("Parsed Action: %s", sts_action_to_string(params.action));

    // Step 3: Handle authentication
    if (params.signature[0] && params.signature_version[0]) {
        log_debug("Using query-style authentication — verifying HMAC signature");
    
        if (!validate_query_signature(body, &params)) {
            log_warn("Signature mismatch for query-style authentication");
            respond_with_aws_error(ssl, AWS_ERROR_SIGNATURE_DOES_NOT_MATCH);
            return;
        }
    } else {
        // === SigV4 Authorization header ===
        char auth_header_raw[1024];
        if (!match_header_param(request, "Authorization", auth_header_raw, sizeof(auth_header_raw))) {
            log_warn("Missing Authorization header");
            respond_with_aws_error(ssl, AWS_ERROR_MISSING_AUTHENTICATION_TOKEN);
            return;
        }

        AuthorizationHeader auth_header;
        ErrorCode err = authorization_header_parse(auth_header_raw, &auth_header);
        if (err != ERROR_NONE) {
            log_warn("Failed to parse Authorization header: %d", err);
            respond_with_aws_error(ssl, AWS_ERROR_SIGNATURE_DOES_NOT_MATCH);
            return;
        }

        err = validate_authorization_credentials(&auth_header);
        switch (err) {
            case ERROR_NONE:
                break;
            case ERROR_INVALID_CLIENT_TOKEN_ID:
                log_warn("Invalid access key ID in Authorization header");
                respond_with_aws_error(ssl, AWS_ERROR_INVALID_CLIENT_TOKEN_ID);
                return;
            case ERROR_CREDENTIALS_NOT_FOUND:
                log_error("Credentials not loaded from environment");
                respond_with_aws_error(ssl, AWS_ERROR_INTERNAL_FAILURE);
                return;
            default:
                log_error("Unknown error during credential validation: %d", err);
                respond_with_aws_error(ssl, AWS_ERROR_UNKNOWN);
                return;
        }
    }

    // Step 4: Dispatch
    switch (params.action) {
        case STS_ACTION_GET_CALLER_IDENTITY:
            log_info("Handling GetCallerIdentity");

            const char *resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/xml\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            SSL_write(ssl, resp, strlen(resp));
            break;

        default:
            log_warn("Unknown or unsupported Action");
            respond_with_aws_error(ssl, AWS_ERROR_INVALID_ACTION);
            break;
    }
}
