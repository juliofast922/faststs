#include "api/routes/sts_dispatcher.h"
#include "models/get_caller_identity.h"
#include "aws/aws_error.h"
#include "models/common_params.h"
#include "aws/sigv4.h"
#include "utils.h"
#include "http.h"
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
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE, NULL);
        return;
    }
    body += 4;

    // Step 2: Parse and validate parameters
    AWSCommonParams params;
    if (!parse_common_params(body, &params)) {
        log_warn("Failed to parse common parameters");
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE, NULL);
        return;
    }

    if (!validate_common_params(&params)) {
        log_warn("Validation failed for parameters");
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE, NULL);
        return;
    }

    log_debug("Parsed Action: %s", sts_action_to_string(params.action));

    // Step 3: Handle authentication
    if (params.signature[0] && params.signature_version[0]) {
        log_debug("Using query-style authentication — verifying HMAC signature");
    
        if (!validate_query_signature(body, &params)) {
            log_warn("Signature mismatch for query-style authentication");
            respond_with_aws_error(ssl, AWS_ERROR_SIGNATURE_DOES_NOT_MATCH, NULL);
            return;
        }
    } else {
        // === SigV4 Authorization header ===
        char auth_header_raw[1024];
        if (!match_header_param(request, "Authorization", auth_header_raw, sizeof(auth_header_raw))) {
            log_warn("Missing Authorization header");
            respond_with_aws_error(ssl, AWS_ERROR_MISSING_AUTHENTICATION_TOKEN, NULL);
            return;
        }

        AuthorizationHeader auth_header;
        ErrorCode err = authorization_header_parse(auth_header_raw, &auth_header);
        if (err != ERROR_NONE) {
            log_warn("Failed to parse Authorization header: %d", err);
            respond_with_aws_error(ssl, AWS_ERROR_SIGNATURE_DOES_NOT_MATCH, NULL);
            return;
        }

        err = validate_authorization_credentials(&auth_header);
        switch (err) {
            case ERROR_NONE:
                break;
            case ERROR_INVALID_CLIENT_TOKEN_ID:
                log_warn("Invalid access key ID in Authorization header");
                respond_with_aws_error(ssl, AWS_ERROR_INVALID_CLIENT_TOKEN_ID, NULL);
                return;
            case ERROR_CREDENTIALS_NOT_FOUND:
                log_error("Credentials not loaded from environment");
                respond_with_aws_error(ssl, AWS_ERROR_INTERNAL_FAILURE, NULL);
                return;
            default:
                log_error("Unknown error during credential validation: %d", err);
                respond_with_aws_error(ssl, AWS_ERROR_UNKNOWN, NULL);
                return;
        }
    }

    // Step 4: Dispatch
    switch (params.action) {
        case STS_ACTION_GET_CALLER_IDENTITY:
            // TODO: Add cache flow decision.
            log_info("Forwarding GetCallerIdentity to AWS STS");

            HttpRequest aws_req = {
                .url = "https://sts.amazonaws.com/",
                .method = "POST",
                .timeout_seconds = 5,
                .body = (char *)body,
                .body_len = strlen(body),
                .headers = NULL,
            };
        
            // Copy forward relevant headers
            const char *content_type = "Content-Type: application/x-www-form-urlencoded";
            const char *host = "Host: sts.amazonaws.com";
        
            char auth_header[1024] = {0};
            if (params.signature[0]) {
                // Query-style: no Authorization header
                aws_req.headers = (const char *[]){
                    (char *)content_type,
                    (char *)host,
                    NULL
                };
            } else {
                if (!match_header_param(request, "Authorization", auth_header, sizeof(auth_header))) {
                    log_warn("Authorization header missing for forwarding");
                    respond_with_aws_error(ssl, AWS_ERROR_MISSING_AUTHENTICATION_TOKEN, NULL);
                    return;
                }
        
                char full_auth_header[1050];
                snprintf(full_auth_header, sizeof(full_auth_header), "Authorization: %s", auth_header);
        
                aws_req.headers = (const char *[]){
                    (char *)content_type,
                    (char *)host,
                    full_auth_header,
                    NULL
                };
            }
        
            HttpResponse aws_res = {0};
            ErrorCode err = http_execute(&aws_req, &aws_res);
            if (err != ERROR_NONE) {
                log_error("Forwarding to AWS STS failed");
                respond_with_aws_error(ssl, AWS_ERROR_INTERNAL_FAILURE, NULL);
                return;
            }

            // Check if AWS responded with an error
            char aws_code[64], aws_msg[512];
            extract_aws_error_info(aws_res.body, aws_code, sizeof(aws_code), aws_msg, sizeof(aws_msg));

            if (aws_code[0] != '\0') {
                AWSError aws_error = aws_error_from_code(aws_code);
                log_warn("AWS returned error: %s - %s", aws_code, aws_msg);
                respond_with_aws_error(ssl, aws_error, aws_msg[0] ? aws_msg : NULL);
                http_response_free(&aws_res);
                return;
            }
        
            // Deserialize and simulate caching
            GetCallerIdentity identity = get_caller_identity_create();
            ErrorCode parse_err = get_caller_identity_deserialize_xml(&identity, aws_res.body);
            if (parse_err == ERROR_NONE) {
                // TODO: Store `identity` in cache using `params.access_key_id` as key
                log_debug("Successfully parsed GetCallerIdentity for caching");
            } else {
                log_warn("Failed to parse AWS response for caching: %d", parse_err);
            }

            // Serialize and respond with our own XML
            char response_buf[1024];
            ErrorCode serialize_err = get_caller_identity_serialize_xml(&identity, response_buf, sizeof(response_buf));
            if (serialize_err != ERROR_NONE) {
                log_error("Serialization failed: %s", error_to_string(serialize_err));
                respond_with_aws_error(ssl, AWS_ERROR_INTERNAL_FAILURE, NULL);
                http_response_free(&aws_res);
                return;
            }

            char final_response[1200];
            snprintf(final_response, sizeof(final_response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/xml\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "%s",
                    strlen(response_buf), response_buf);

            SSL_write(ssl, final_response, strlen(final_response));
            http_response_free(&aws_res);
            break;

        default:
            log_warn("Unknown or unsupported Action");
            respond_with_aws_error(ssl, AWS_ERROR_INVALID_ACTION, NULL);
            break;
    }
}
