// src/models/user.c

#include <stdio.h>
#include <string.h>
#include "models/user.h"

// Vtable
static ModelInterface user_model_interface = {
    .deserialize_xml = user_deserialize_xml
};

// Helpers para parsing XML simple
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

// Implementación de la interfaz
void user_deserialize_xml(void *self, const char *xml) {
    User *user = (User *)self;

    extract_tag_text(xml, "UserId", user->user_id, sizeof(user->user_id));
    extract_tag_text(xml, "Path", user->path, sizeof(user->path));
    extract_tag_text(xml, "UserName", user->user_name, sizeof(user->user_name));
    extract_tag_text(xml, "Arn", user->arn, sizeof(user->arn));
    extract_tag_text(xml, "CreateDate", user->create_date, sizeof(user->create_date));
    extract_tag_text(xml, "PasswordLastUsed", user->password_last_used, sizeof(user->password_last_used));

    user->has_password_last_used = user->password_last_used[0] != '\0';
}

// Constructor
User user_create() {
    User user = {0};
    user.vtable = &user_model_interface;
    return user;
}
