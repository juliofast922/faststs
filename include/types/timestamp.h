// types/timestamp.h

#ifndef AWS_STS_TIMESTAMP_H
#define AWS_STS_TIMESTAMP_H

#include <time.h>

/**
 * @brief Validates whether the given string is a valid ISO 8601 UTC timestamp.
 *
 * Expected format: YYYY-MM-DDThh:mm:ssZ (e.g., 2025-08-05T21:00:00Z)
 *
 * @param input The timestamp string to validate.
 * @return 1 if valid, 0 otherwise.
 */
int timestamp_is_valid_iso8601(const char *input);

/**
 * @brief Checks if the timestamp is within an acceptable time skew window.
 *
 * This function ensures the provided ISO 8601 timestamp is not expired
 * relative to the current system time, allowing for some clock skew.
 *
 * @param input         ISO 8601 UTC timestamp string.
 * @param skew_seconds  Allowed time skew in seconds.
 * @return 1 if the timestamp is still valid (not expired), 0 otherwise.
 */
int timestamp_is_not_expired(const char *input, int skew_seconds);

#endif // AWS_STS_TIMESTAMP_H