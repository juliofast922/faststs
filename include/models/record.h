#ifndef RECORD_H
#define RECORD_H

#include "error.h"
#include <stddef.h>

/**
 * @brief Interface for a generic WAL record.
 * 
 * This interface defines the essential operations that a record type must implement 
 * to support JSON (de)serialization, deep cloning, equality comparison, and key extraction. 
 * It is designed to support polymorphism in C through function pointers.
 */
typedef struct RecordInterface {

    /**
     * @brief Deserializes a JSON string into the current record.
     * 
     * @param self Pointer to the record instance.
     * @param json_input JSON string to parse and load into the record.
     * @return ErrorCode indicating success or failure of the operation.
     */
    ErrorCode (*deserialize_json)(void *self, const char *json_input);

    /**
     * @brief Serializes the record into a JSON string.
     * 
     * @param self Pointer to the record instance.
     * @param json_buffer Buffer to write the serialized JSON string into.
     * @param json_buffer_size Maximum number of bytes to write into the buffer.
     * @return ErrorCode indicating success or failure of the operation.
     */
    ErrorCode (*serialize_json)(void *self, char *json_buffer, size_t json_buffer_size);

    /**
     * @brief Frees any dynamically allocated memory associated with the record.
     * 
     * @param self Pointer to the record instance.
     */
    void (*free)(void *self);

    /**
     * @brief Creates a deep copy of the record.
     * 
     * @param self Pointer to the source record.
     * @return Pointer to a newly allocated copy of the record (must be freed by caller), or NULL on failure.
     */
    void *(*clone)(void *self);

    /**
     * @brief Compares two records for equality.
     * 
     * @param self Pointer to the first record.
     * @param other Pointer to the second record.
     * @return 1 if records are equal, 0 otherwise.
     */
    int (*equals)(void *self, void *other);

    /**
     * @brief Retrieves the primary key of the record.
     * 
     * This is typically a unique identifier like "user:123".
     * 
     * @param self Pointer to the record instance.
     * @param key_buffer Buffer to write the key string into.
     * @param key_buffer_size Maximum size of the key_buffer.
     * @return ErrorCode indicating success or failure of the operation.
     */
    ErrorCode (*get_key)(void *self, char *key_buffer, size_t key_buffer_size);

} RecordInterface;

#endif // RECORD_H
