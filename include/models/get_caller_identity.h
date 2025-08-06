#ifndef GET_CALLER_IDENTITY_MODEL_H
#define GET_CALLER_IDENTITY_MODEL_H

#include "error.h"
#include "model.h"
#include "types/arn.h"

/**
 * @brief Represents the AWS STS GetCallerIdentity response.
 */
typedef struct {
    ModelInterface *vtable;

    char user_id[64];  ///< The unique identifier of the calling entity (required)
    char account[32];  ///< The AWS account ID number of the calling entity (required)
    Arn arn;     ///< The ARN of the calling entity (required)
} GetCallerIdentity;

/**
 * @brief Constructs a new GetCallerIdentity instance and sets its vtable.
 */
GetCallerIdentity get_caller_identity_create();

/**
 * @brief Deserializes a GetCallerIdentity object from XML input.
 */
ErrorCode get_caller_identity_deserialize_xml(void *self, const char *xml);

ErrorCode get_caller_identity_serialize_xml(const GetCallerIdentity *id, char *buf, size_t buf_len);

#endif // GET_CALLER_IDENTITY_MODEL_H
