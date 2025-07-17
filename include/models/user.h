#ifndef USER_H
#define USER_H

#include "error.h"
#include "model.h"
#include "types/arn.h"  // Añadido para usar Arn

/**
 * @brief Represents an AWS IAM User object parsed from XML.
 *
 * This struct implements the Model interface via a vtable pointer.
 * All fields are fixed-size strings to avoid dynamic allocation.
 */
typedef struct {
    ModelInterface *vtable;

    char user_id[64];             ///< Unique user identifier (required)
    char path[128];               ///< Path of the user (required)
    char user_name[64];           ///< IAM user name (required)
    Arn arn;                      ///< Amazon Resource Name (required)
    char create_date[32];         ///< Creation timestamp (required)
    char password_last_used[32];  ///< Last password usage (optional)
    int has_password_last_used;   ///< Flag indicating if password_last_used is set
} User;

/**
 * @brief Constructs and returns a new User instance.
 *
 * Initializes all fields to zero and sets the vtable.
 *
 * @return User  A fully initialized User object.
 */
User user_create();

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
ErrorCode user_deserialize_xml(void *self, const char *xml);

#endif // USER_H
