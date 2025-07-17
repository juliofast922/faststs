#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

/**
 * @brief Extracts text content between <tag> and </tag> from XML input.
 *
 * Example:
 *   Input: "<UserId>abc</UserId>", tag: "UserId" → Output: "abc"
 *
 * @param xml       Pointer to the XML string.
 * @param tag       Tag name to search.
 * @param out       Buffer to store extracted text.
 * @param out_size  Size of the output buffer.
 */
void extract_tag_text(const char *xml, const char *tag, char *out, size_t out_size);

#endif // UTILS_H
