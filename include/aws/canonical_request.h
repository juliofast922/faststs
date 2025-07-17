#ifndef AWS_CANONICAL_REQUEST_H
#define AWS_CANONICAL_REQUEST_H

#include <stddef.h>
#include "error.h"

typedef struct {
    const char *method;            // GET, POST, etc.
    const char *uri;               // Canonical URI (e.g. "/")
    const char *query_string;      // Canonical Query (sorted & encoded)
    const char *headers;           // Canonical headers string
    const char *signed_headers;    // host;x-amz-date
    const char *payload_hash;      // SHA256 of body, hex encoded
} CanonicalRequest;

/**
 * @brief Builds the full canonical request string.
 * @param cr Pointer to CanonicalRequest input
 * @param out_buffer Output string buffer
 * @param out_size Size of output buffer
 * @return ErrorCode
 */
ErrorCode canonical_request_build(
    const CanonicalRequest *cr,
    char *out_buffer,
    size_t out_size
);

#endif // AWS_CANONICAL_REQUEST_H
