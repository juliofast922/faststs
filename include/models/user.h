#ifndef USER_H
#define USER_H

#include "error.h"
#include "model.h"

/**
 * @brief Represents an AWS IAM User object parsed from XML.
 *
 * This struct implements the Model interface via a vtable pointer.
 * All fields are fixed-size strings to avoid dynamic allocation.
 */
typedef struct {
    ModelInterface *vtable;  ///< Pointer to Model interface (deserialize_xml)

    char user_id[64];             ///< Unique user identifier (required)
    char path[128];               ///< Path of the user (required)
    char user_name[64];           ///< IAM user name (required)
    char arn[256];                ///< Amazon Resource Name (required)
    char create_date[32];         ///< Creation timestamp (required)
    char password_last_used[32];  ///< Last password usage (optional)
    int has_password_last_used;   ///< Flag indicating if password_last_used is set
} User;

/**
 * @brief Constructs a new User instance and sets its vtable.
 *
 * @return User  A zero-initialized User struct with vtable assigned.
 */
User user_create();

/**
 * @brief Deserializes a User object from XML input.
 *
 * Parses known AWS IAM User fields. Logs an error if required fields are missing.
 *
 * @param self Pointer to the User object to populate.
 * @param xml  Raw XML string to parse.
 */
ErrorCode user_deserialize_xml(void *self, const char *xml);

#endif // USER_H
