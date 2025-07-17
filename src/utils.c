#include <string.h>
#include <stdio.h>
#include "utils.h"

/**
 * @brief Extracts text content between <tag> and </tag> from XML input.
 *
 * @param xml       Pointer to the XML string.
 * @param tag       Tag name to search.
 * @param out       Buffer to store extracted text.
 * @param out_size  Size of the output buffer.
 */
void extract_tag_text(const char *xml, const char *tag, char *out, size_t out_size) {
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
