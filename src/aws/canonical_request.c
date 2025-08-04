#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "error.h"
#include "aws/canonical_request.h"

ErrorCode canonical_request_build(
    const CanonicalRequest *cr,
    char *out_buffer,
    size_t out_size
) {
    if (!cr || !out_buffer || out_size == 0)
        return ERROR_VALIDATION_FAILED;

    int written = snprintf(out_buffer, out_size,
        "%s\n"      // HTTP method
        "%s\n"      // URI
        "%s\n"      // Query string
        "%s\n"      // Canonical headers (must end in \n)
        "%s\n"      // Signed headers
        "%s",       // Payload hash (no \n at end)
        cr->method,
        cr->uri,
        cr->query_string,
        cr->headers,
        cr->signed_headers,
        cr->payload_hash
    );

    if (written < 0 || (size_t)written >= out_size)
        return ERROR_VALIDATION_FAILED;

    log_debug("CanonicalRequest built:\n%s", out_buffer);
    return ERROR_NONE;
}
