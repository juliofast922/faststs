#include "error.h"
#include "aws/credentials.h"
#include "aws/aws_error.h"
#include "utils.h"
#include "logger.h"
#include <string.h>
#include <stdio.h>


ErrorCode load_credentials(AwsCredentials *creds) {
    if (!creds) return ERROR_CREDENTIALS_NOT_FOUND;

    const char *env_access = get_env_str("ACCESS_KEY_ID");
    const char *env_secret = get_env_str("SECRET_ACCESS_KEY");

    if (!env_access || !env_secret || !*env_access || !*env_secret) {
        log_error("Missing ACCESS_KEY_ID or SECRET_ACCESS_KEY in environment");
        return ERROR_CREDENTIALS_NOT_FOUND;
    }

    strncpy(creds->access_key, env_access, sizeof(creds->access_key) - 1);
    creds->access_key[sizeof(creds->access_key) - 1] = '\0';

    strncpy(creds->secret_key, env_secret, sizeof(creds->secret_key) - 1);
    creds->secret_key[sizeof(creds->secret_key) - 1] = '\0';

    log_debug("Loaded AWS credentials from environment");
    return ERROR_NONE;
}