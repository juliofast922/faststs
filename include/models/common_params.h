// models/common_params.h

#ifndef AWS_STS_COMMON_PARAMS_H
#define AWS_STS_COMMON_PARAMS_H

#include "types/action.h"

/**
 * @brief Represents the common parameters used in AWS STS API requests.
 *
 * This struct is typically populated from parsed HTTP form/query body data.
 * It supports both standard SigV2 fields and STS-specific fields.
 */
typedef struct {
    STSAction action;                 /**< Parsed STS action (e.g. GetCallerIdentity) */
    char version[16];                /**< API version (e.g. "2011-06-15") */
    char access_key_id[128];         /**< AWS Access Key ID */
    char signature[256];             /**< Computed signature (SigV2 or custom) */
    char signature_method[32];       /**< Signature method (e.g. "HmacSHA256") */
    char signature_version[4];       /**< Signature version (e.g. "2") */
    char timestamp[64];              /**< ISO 8601 formatted timestamp */
    char security_token[2048];       /**< Optional security token (e.g. for temporary creds) */
    char session_token[2048];        /**< Alias for security token (interchangeable) */
    int duration_seconds;            /**< Optional duration for temporary credentials */
} AWSCommonParams;

/**
 * @brief Validates required fields in AWSCommonParams.
 *
 * Performs checks on version, action, timestamp, and (optionally) signature presence.
 *
 * @param params Pointer to parsed AWSCommonParams.
 * @return 1 if valid, 0 if invalid.
 */
int validate_common_params(const AWSCommonParams *params);

/**
 * @brief Parses AWS STS parameters from a URL-encoded body string.
 *
 * Supports key=value&key2=value2 style format. Fills in AWSCommonParams.
 *
 * @param body URL-encoded request body.
 * @param params Output struct to fill.
 * @return 1 if successful, 0 on parse error.
 */
int parse_common_params(const char *body, AWSCommonParams *params);

#endif // AWS_STS_COMMON_PARAMS_H
