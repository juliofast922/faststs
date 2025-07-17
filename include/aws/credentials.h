#ifndef AWS_CREDENTIALS_H
#define AWS_CREDENTIALS_H

#include "error.h"

/**
 * @brief Holds AWS access credentials.
 */
typedef struct {
    char access_key[64];
    char secret_key[128];
} AwsCredentials;

/**
 * @brief Loads AWS credentials from a .env file or environment variables.
 *
 * Priority:
 *   1. If env_path is provided, it attempts to read ACCESS_KEY_ID and SECRET_ACCESS_KEY from that file.
 *   2. If not found or not provided, it falls back to getenv().
 *
 * @param creds     Pointer to the AwsCredentials struct to populate.
 * @param env_path  Optional path to a .env file.
 * @return ErrorCode indicating success or failure.
 */
ErrorCode load_credentials(AwsCredentials *creds, const char *env_path);

#endif // AWS_CREDENTIALS_H
