// include/models/user.h

#ifndef USER_H
#define USER_H

#include "model.h"

typedef struct {
    ModelInterface *vtable;

    char user_id[64];
    char path[128];
    char user_name[64];
    char arn[256];
    char create_date[32];
    char password_last_used[32]; // optional
    int has_password_last_used;
} User;

User user_create();
void user_deserialize_xml(void *self, const char *xml);

#endif
