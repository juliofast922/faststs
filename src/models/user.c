#include <stdio.h>
#include <string.h>
#include "logger.h"
#include "utils.h"

#include "models/user.h"
#include "types/arn.h"

// Vtable for User implementing the Model interface
static ModelInterface user_model_interface = {
    .deserialize_xml = user_deserialize_xml
};

ErrorCode user_deserialize_xml(void *self, const char *xml) {
    User *user = (User *)self;

    extract_tag_text(xml, "UserId", user->user_id, sizeof(user->user_id));
    extract_tag_text(xml, "Path", user->path, sizeof(user->path));
    extract_tag_text(xml, "UserName", user->user_name, sizeof(user->user_name));

    char arn_buffer[ARN_MAX_LEN + 1];
    extract_tag_text(xml, "Arn", arn_buffer, sizeof(arn_buffer));
    ErrorCode arn_err = arn_set(&user->arn, arn_buffer);

    extract_tag_text(xml, "CreateDate", user->create_date, sizeof(user->create_date));
    extract_tag_text(xml, "PasswordLastUsed", user->password_last_used, sizeof(user->password_last_used));
    user->has_password_last_used = user->password_last_used[0] != '\0';

    if (user->user_id[0] == '\0' || user->user_name[0] == '\0' ||
        arn_err != ERROR_NONE || user->create_date[0] == '\0') {

        if (arn_err == ERROR_VALIDATION_FAILED) {
            log_error("Invalid ARN format in User: '%s'", arn_buffer);
            return ERROR_VALIDATION_FAILED;
        }

        log_error("Failed to deserialize User: missing required fields. user_id='%s', user_name='%s', arn='%s', create_date='%s'",
                  user->user_id, user->user_name, arn_buffer, user->create_date);
        return ERROR_DESERIALIZE_MISSING_FIELD;
    }

    return ERROR_NONE;
}

User user_create() {
    User user = {0};
    user.vtable = &user_model_interface;
    return user;
}
