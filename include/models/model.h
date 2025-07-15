#ifndef MODEL_H
#define MODEL_H

#include "error.h"

/**
 * @brief Interface for domain models that support XML deserialization.
 *
 * Any struct that implements this interface must define the `deserialize_xml` function.
 * This allows a generic mechanism to transform raw XML into structured domain data.
 */
typedef struct ModelInterface {
    /**
     * @brief Parses XML and populates the given struct instance.
     *
     * @param self Pointer to the struct implementing the interface.
     * @param xml  Raw XML string to deserialize.
     * @return ErrorCode indicating success or failure.
     */
    ErrorCode (*deserialize_xml)(void *self, const char *xml);
} ModelInterface;

#endif // MODEL_H
