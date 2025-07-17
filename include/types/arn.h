#ifndef ARN_H
#define ARN_H

#include <stddef.h>
#include "error.h"

#define ARN_MAX_LEN 2048
#define ARN_MIN_LEN 20

/**
 * @brief Strongly-typed ARN with validation.
 */
typedef struct {
    char value[ARN_MAX_LEN + 1];  ///< Null-terminated ARN string
} Arn;

/**
 * @brief Validates whether a string is a valid AWS ARN.
 *
 * Checks length constraints and character range.
 *
 * @param input  Input string to validate.
 * @return 1 if valid, 0 otherwise.
 */
int arn_is_valid(const char *input);

/**
 * @brief Sets the ARN value if valid.
 *
 * @param arn    Pointer to Arn struct.
 * @param input  Input ARN string.
 * @return ERROR_NONE if valid and copied, ERROR_VALIDATION_FAILED otherwise.
 */
ErrorCode arn_set(Arn *arn, const char *input);

#endif // ARN_H
