#include "error.h"
#include "aws/credentials.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

ErrorCode load_credentials(AwsCredentials *creds, const char *env_path) {
    if (!creds) return ERROR_CREDENTIALS_NOT_FOUND;

    char access_key[64] = {0};
    char secret_key[128] = {0};

    int found = 0;

    if (env_path) {
        found += get_env_from_file(env_path, "ACCESS_KEY_ID", access_key, sizeof(access_key));
        found += get_env_from_file(env_path, "SECRET_ACCESS_KEY", secret_key, sizeof(secret_key));
    }

    if (!found || access_key[0] == '\0' || secret_key[0] == '\0') {
        const char *env_access = get_env_str("ACCESS_KEY_ID");
        const char *env_secret = get_env_str("SECRET_ACCESS_KEY");

        if (env_access) strncpy(access_key, env_access, sizeof(access_key) - 1);
        if (env_secret) strncpy(secret_key, env_secret, sizeof(secret_key) - 1);
    }

    if (access_key[0] != '\0' && secret_key[0] != '\0') {
        strncpy(creds->access_key, access_key, sizeof(creds->access_key) - 1);
        strncpy(creds->secret_key, secret_key, sizeof(creds->secret_key) - 1);
        return ERROR_NONE;
    }

    return ERROR_CREDENTIALS_NOT_FOUND;
}
