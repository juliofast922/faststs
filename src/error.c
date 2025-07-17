#include "error.h"

const char* error_to_string(ErrorCode code) {
    switch (code) {
        case ERROR_NONE:
            return "No error";
        case ERROR_DESERIALIZE_MISSING_FIELD:
            return "Missing required field in XML";
        case ERROR_DESERIALIZE_INVALID_FORMAT:
            return "Invalid XML format";
        case ERROR_VALIDATION_FAILED:
            return "Validation failed";
        case ERROR_CREDENTIALS_NOT_FOUND:
            return "AWS credentials not found";
        case ERROR_SIGV4_INVALID_INPUT:
            return "Invalid input for SigV4 signing";
        case ERROR_SIGV4_SIGNING_FAILURE:
            return "SigV4 signing failure";
        case ERROR_HTTP_INVALID_INPUT:
            return "Invalid input for HTTP request";
        case ERROR_HTTP_INIT_FAILED:
            return "Failed to initialize HTTP client";
        case ERROR_HTTP_CURL:
            return "HTTP request failed (curl)";
        case ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}
