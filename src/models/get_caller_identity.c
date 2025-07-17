#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "logger.h"
#include "models/get_caller_identity.h"

// Vtable for GetCallerIdentity implementing the Model interface
static ModelInterface get_caller_identity_interface = {
    .deserialize_xml = get_caller_identity_deserialize_xml
};

ErrorCode get_caller_identity_deserialize_xml(void *self, const char *xml) {
    GetCallerIdentity *id = (GetCallerIdentity *)self;

    extract_tag_text(xml, "UserId", id->user_id, sizeof(id->user_id));
    extract_tag_text(xml, "Account", id->account, sizeof(id->account));
    char arn_buffer[2048 + 1];
    extract_tag_text(xml, "Arn", arn_buffer, sizeof(arn_buffer));
    ErrorCode arn_err = arn_set(&id->arn, arn_buffer);

    if (id->user_id[0] == '\0' || id->account[0] == '\0' || arn_err != ERROR_NONE) {
        if (arn_err == ERROR_VALIDATION_FAILED) {
            log_error("Invalid ARN format: '%s'", arn_buffer);
            return ERROR_VALIDATION_FAILED;
        } else {
            log_error("Failed to deserialize GetCallerIdentity: user_id='%s', account='%s', arn='%s'",
                      id->user_id, id->account, arn_buffer);
            return ERROR_DESERIALIZE_MISSING_FIELD;
        }
    }

    return ERROR_NONE;
}

GetCallerIdentity get_caller_identity_create() {
    GetCallerIdentity identity = {0};
    identity.vtable = &get_caller_identity_interface;
    return identity;
}
