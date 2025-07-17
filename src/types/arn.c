#include <string.h>
#include <stdio.h>
#include "types/arn.h"

/**
 * @brief Validates if the input string is a valid AWS ARN.
 *
 * Performs length check and ensures only valid ASCII characters are present,
 * according to AWS constraints:
 *   - Length: 20–2048 characters
 *   - Pattern: Tab (0x09), LF, CR, ASCII printable characters (0x20–0x7E)
 *
 * Note: This implementation currently validates only the ASCII-safe subset.
 *
 * @param input Input string to validate.
 * @return 1 if valid, 0 otherwise.
 */
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

/**
 * @brief Safely sets the value of an Arn object after validating it.
 *
 * If the input is valid, its value is copied into the `arn` struct.
 * If the input is invalid, the struct remains unchanged and an error is returned.
 *
 * @param arn    Pointer to the Arn struct to populate.
 * @param input  Input ARN string to validate and assign.
 * @return ERROR_NONE on success, or ERROR_VALIDATION_FAILED if input is invalid.
 */
ErrorCode arn_set(Arn *arn, const char *input) {
    if (!arn || !input) return ERROR_VALIDATION_FAILED;

    if (!arn_is_valid(input)) {
        return ERROR_VALIDATION_FAILED;
    }

    strncpy(arn->value, input, ARN_MAX_LEN);
    arn->value[ARN_MAX_LEN] = '\0'; // Ensure null termination
    return ERROR_NONE;
}
