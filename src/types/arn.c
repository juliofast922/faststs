#include <string.h>
#include <stdio.h>
#include "types/arn.h"

int arn_is_valid(const char *input) {
    if (!input) return 0;

    size_t len = strlen(input);
    if (len < ARN_MIN_LEN || len > ARN_MAX_LEN) return 0;

    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = input[i];
        // Allow tab (0x09), LF (0x0A), CR (0x0D), space (0x20) to tilde (0x7E)
        if (ch < 0x09 || (ch > 0x0D && ch < 0x20) || ch > 0x7E) {
            return 0;
        }
    }

    return 1;
}

ErrorCode arn_set(Arn *arn, const char *input) {
    if (!arn || !input) return ERROR_VALIDATION_FAILED;

    if (!arn_is_valid(input)) {
        return ERROR_VALIDATION_FAILED;
    }

    strncpy(arn->value, input, ARN_MAX_LEN);
    arn->value[ARN_MAX_LEN] = '\0'; // Ensure null termination
    return ERROR_NONE;
}
