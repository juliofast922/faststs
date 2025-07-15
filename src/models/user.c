#include <stdio.h>
#include <string.h>
#include "models/user.h"
#include "logger.h"

// Vtable for User implementing the Model interface
static ModelInterface user_model_interface = {
    .deserialize_xml = user_deserialize_xml
};

/**
 * @brief Extracts text content between <tag> and </tag> from XML input.
 *
 * @param xml       Pointer to the XML string.
 * @param tag       Tag name to search.
 * @param out       Buffer to store extracted text.
 * @param out_size  Size of the output buffer.
 */
static void extract_tag_text(const char *xml, const char *tag, char *out, size_t out_size) {
    char open_tag[64], close_tag[64];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

    char *start = strstr(xml, open_tag);
    char *end = strstr(xml, close_tag);

    if (start && end && end > start) {
        start += strlen(open_tag);
        size_t len = end - start;
        if (len >= out_size) len = out_size - 1;
        strncpy(out, start, len);
        out[len] = '\0';
    } else {
        out[0] = '\0';
    }
}

/**
 * @brief Deserializes a User object from XML.
 *
 * Expects XML in the format defined by AWS IAM User API response.
 * Logs and returns an error code if required fields are missing.
 *
 * @param self  Pointer to the User object.
 * @param xml   Raw XML string to parse.
 * @return ErrorCode indicating success or failure.
 */
ErrorCode user_deserialize_xml(void *self, const char *xml) {
    User *user = (User *)self;

    // Parse each expected XML tag
    extract_tag_text(xml, "UserId", user->user_id, sizeof(user->user_id));
    extract_tag_text(xml, "Path", user->path, sizeof(user->path));
    extract_tag_text(xml, "UserName", user->user_name, sizeof(user->user_name));
    extract_tag_text(xml, "Arn", user->arn, sizeof(user->arn));
    extract_tag_text(xml, "CreateDate", user->create_date, sizeof(user->create_date));
    extract_tag_text(xml, "PasswordLastUsed", user->password_last_used, sizeof(user->password_last_used));

    user->has_password_last_used = user->password_last_used[0] != '\0';

    // Validate required fields
    if (user->user_id[0] == '\0' || user->user_name[0] == '\0' ||
        user->arn[0] == '\0' || user->create_date[0] == '\0') {

        log_error("Failed to deserialize User: missing required fields. user_id='%s', user_name='%s', arn='%s', create_date='%s'",
                  user->user_id, user->user_name, user->arn, user->create_date);

        return ERROR_DESERIALIZE_MISSING_FIELD;
    }

    return ERROR_NONE;
}

/**
 * @brief Constructs and returns a new User instance.
 *
 * Initializes all fields to zero and sets the vtable.
 *
 * @return User  A fully initialized User object.
 */
User user_create() {
    User user = {0};
    user.vtable = &user_model_interface;
    return user;
}
