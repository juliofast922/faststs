#ifndef AWS_SIGV4_H
#define AWS_SIGV4_H

#include <stddef.h>

#include "error.h"
#include "aws/credentials.h"

/**
 * @brief Represents a fully constructed AWS SigV4 Authorization header.
 */
typedef struct {
    char value[1024];          // Full header string (as received or built)
    char access_key_id[128];   // From Credential=
    char scope[256];           // From Credential=.../<scope>
    char signed_headers[256];  // SignedHeaders=...
    char signature[65];        // Signature=...
} AuthorizationHeader;

/**
 * @brief Builds a SigV4 AuthorizationHeader struct.
 *
 * @param creds              AWS credentials.
 * @param amz_date           Timestamp in format: 20250717T210000Z
 * @param date               Date portion: 20250717
 * @param region             AWS region (e.g., "us-east-1")
 * @param service            AWS service (e.g., "sts")
 * @param canonical_request  CanonicalRequest string (already SHA256'd body)
 * @param out_header         Output header struct to fill.
 * @return ErrorCode indicating success or failure.
 */
ErrorCode authorization_header_build(
    const AwsCredentials *creds,
    const char *amz_date,
    const char *date,
    const char *region,
    const char *service,
    const char *canonical_request,
    AuthorizationHeader *out_header
);

/**
 * @brief Returns a pointer to the full header string (for use in HTTP).
 */
const char *authorization_header_str(const AuthorizationHeader *header);

// === Crypto Helpers ===

/**
 * @brief Computes SHA256 hash of a string and outputs as hex string.
 *
 * @param data      Input data.
 * @param out_hex   Output buffer (65+ bytes for null-terminated hex).
 */
void sha256_hex(const char *data, char *out_hex);

/**
 * @brief Computes HMAC-SHA256 digest.
 *
 * @param key     Secret key.
 * @param key_len Length of key.
 * @param msg     Message to sign.
 * @param out     Output: 32-byte binary digest.
 */
void hmac_sha256(const unsigned char *key, int key_len, const char *msg, unsigned char *out);

// === Incoming Header Parser ===

/**
 * @brief Parses a SigV4 Authorization header string into structured components.
 *
 * @param header_str  Raw Authorization header string.
 * @param out_header  Output structure to populate.
 * @return ErrorCode indicating parse success/failure.
 */
ErrorCode authorization_header_parse(const char *header_str, AuthorizationHeader *out_header);

/**
 * @brief Validates access key format and signature format inside header.
 *
 * @param header Parsed AuthorizationHeader to validate.
 * @return ErrorCode if validation fails or is malformed.
 */
ErrorCode validate_authorization_credentials(const AuthorizationHeader *header);

/**
 * @brief Converts binary data to lowercase hexadecimal string.
 *
 * @param bytes     Input binary buffer.
 * @param len       Number of bytes to convert.
 * @param out_hex   Output buffer (must be at least len*2+1).
 */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *out_hex);

#endif // AWS_SIGV4_H
