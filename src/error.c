#include "error.h"

/**
 * @brief Converts an ErrorCode enum to a human-readable string.
 */
const char* error_to_string(ErrorCode code) {
    switch (code) {
        case ERROR_NONE:
            return "No error";
        case ERROR_DESERIALIZE_MISSING_FIELD:
            return "Missing required field in XML";
        case ERROR_DESERIALIZE_INVALID_FORMAT:
            return "Invalid XML format";
        case ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}
