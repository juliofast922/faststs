// types/action.h

#ifndef AWS_STS_ACTION_H
#define AWS_STS_ACTION_H

/**
 * @brief Enum representing supported AWS STS actions.
 *
 * These values correspond to known STS API operations. If an unrecognized action
 * is encountered during parsing, `STS_ACTION_INVALID` is used.
 */
typedef enum {
    STS_ACTION_ASSUME_ROLE,                    /**< sts:AssumeRole */
    STS_ACTION_ASSUME_ROLE_WITH_SAML,          /**< sts:AssumeRoleWithSAML */
    STS_ACTION_ASSUME_ROLE_WITH_WEB_IDENTITY,  /**< sts:AssumeRoleWithWebIdentity */
    STS_ACTION_DECODE_AUTHORIZATION_MESSAGE,   /**< sts:DecodeAuthorizationMessage */
    STS_ACTION_GET_ACCESS_KEY_INFO,            /**< sts:GetAccessKeyInfo */
    STS_ACTION_GET_CALLER_IDENTITY,            /**< sts:GetCallerIdentity */
    STS_ACTION_GET_FEDERATION_TOKEN,           /**< sts:GetFederationToken */
    STS_ACTION_GET_SESSION_TOKEN,              /**< sts:GetSessionToken */
    STS_ACTION_INVALID                         /**< Invalid or unrecognized action */
} STSAction;

/**
 * @brief Converts an STSAction enum value to a string.
 *
 * @param action Enum value to convert.
 * @return Corresponding string literal (e.g., "GetCallerIdentity").
 */
const char *sts_action_to_string(STSAction action);

/**
 * @brief Parses an input string into an STSAction enum value.
 *
 * @param input Input action string (case-sensitive).
 * @return Parsed enum value, or STS_ACTION_INVALID if unrecognized.
 */
STSAction sts_action_from_string(const char *input);

/**
 * @brief Checks if the input string is a valid STS action.
 *
 * @param input Action string to validate.
 * @return 1 if valid, 0 if invalid.
 */
int sts_action_is_valid(const char *input);

#endif // AWS_STS_ACTION_H
