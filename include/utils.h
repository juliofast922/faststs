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

/**
 * @brief Gets an environment variable from the system or returns NULL.
 *
 * @param key Name of the environment variable (e.g., "LOG_LEVEL")
 * @return Pointer to value string or NULL if not found.
 */
const char *get_env_str(const char *key);

/**
 * @brief Reads a key=value pair from a .env file.
 *
 * Example line: MY_KEY=some_value
 *
 * @param filename Path to the .env file.
 * @param key      Name of the variable to find.
 * @param out      Output buffer to store the value (null-terminated).
 * @param out_size Size of the output buffer.
 * @return 1 if found and stored, 0 if not found or error.
 */
int get_env_from_file(const char *filename, const char *key, char *out, size_t out_size);

/**
 * @brief Parses a URL-encoded key=value body string and extracts a parameter.
 *
 * For example: extract from "Action=Test&Version=2011-06-15"
 *
 * @param body The full body string.
 * @param key The key to search for.
 * @param out Buffer to store the value.
 * @param out_size Size of the output buffer.
 * @return int 1 if key found, 0 otherwise.
 */
int match_form_param(const char *body, const char *key, char *out, size_t out_size);

#endif // UTILS_H
