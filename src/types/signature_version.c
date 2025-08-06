// types/signature_version.c

#include "types/signature_version.h"
#include <string.h>

int signature_version_is_valid(const char *input) {
    return input && (strcmp(input, "4") == 0 || strcmp(input, "2") == 0);
}
