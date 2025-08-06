// types/action.c

#include "types/action.h"
#include <string.h>

const char *sts_action_to_string(STSAction action) {
    switch (action) {
        case STS_ACTION_ASSUME_ROLE: return "AssumeRole";
        case STS_ACTION_ASSUME_ROLE_WITH_SAML: return "AssumeRoleWithSAML";
        case STS_ACTION_ASSUME_ROLE_WITH_WEB_IDENTITY: return "AssumeRoleWithWebIdentity";
        case STS_ACTION_DECODE_AUTHORIZATION_MESSAGE: return "DecodeAuthorizationMessage";
        case STS_ACTION_GET_ACCESS_KEY_INFO: return "GetAccessKeyInfo";
        case STS_ACTION_GET_CALLER_IDENTITY: return "GetCallerIdentity";
        case STS_ACTION_GET_FEDERATION_TOKEN: return "GetFederationToken";
        case STS_ACTION_GET_SESSION_TOKEN: return "GetSessionToken";
        default: return "Invalid";
    }
}

STSAction sts_action_from_string(const char *input) {
    if (!input) return STS_ACTION_INVALID;

    if (strcmp(input, "AssumeRole") == 0) return STS_ACTION_ASSUME_ROLE;
    if (strcmp(input, "AssumeRoleWithSAML") == 0) return STS_ACTION_ASSUME_ROLE_WITH_SAML;
    if (strcmp(input, "AssumeRoleWithWebIdentity") == 0) return STS_ACTION_ASSUME_ROLE_WITH_WEB_IDENTITY;
    if (strcmp(input, "DecodeAuthorizationMessage") == 0) return STS_ACTION_DECODE_AUTHORIZATION_MESSAGE;
    if (strcmp(input, "GetAccessKeyInfo") == 0) return STS_ACTION_GET_ACCESS_KEY_INFO;
    if (strcmp(input, "GetCallerIdentity") == 0) return STS_ACTION_GET_CALLER_IDENTITY;
    if (strcmp(input, "GetFederationToken") == 0) return STS_ACTION_GET_FEDERATION_TOKEN;
    if (strcmp(input, "GetSessionToken") == 0) return STS_ACTION_GET_SESSION_TOKEN;

    return STS_ACTION_INVALID;
}

int sts_action_is_valid(const char *input) {
    return sts_action_from_string(input) != STS_ACTION_INVALID;
}
