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
 * @brief Loads key=value pairs from a file into the current process environment.
 *
 * @param filename Path to the environment file (e.g., ".env")
 * @return 1 if loaded successfully, 0 if file couldn't be opened.
 */
int load_env_file(const char *filename);

/**
 * @brief Gets an environment variable and parses it as a comma-separated list.
 *        Trims surrounding whitespace from each item.
 *
 * @param key       Environment variable name.
 * @param out       2D array to store results.
 * @param max_items Max number of items to store.
 * @param item_len  Size of each item (e.g., 128 or 256).
 * @return Number of items parsed, or -1 on error.
 */
int get_env_list(const char *key, char *out, size_t max_items, size_t item_len);

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

/**
 * @brief Converts a hexadecimal string into a byte array.
 *
 * For example:
 *   Input:  "68656c6c6f" → Output: {0x68, 0x65, 0x6c, 0x6c, 0x6f}
 *
 * @param hex      Null-terminated hexadecimal string (must be even-length).
 * @param out      Output buffer to store the resulting bytes.
 * @param out_len  Input: size of the `out` buffer; Output: number of bytes written.
 * @return 1 on success, 0 on failure (e.g., invalid hex or insufficient buffer size).
 */
int hexstr_to_bytes(const char *hex, unsigned char *out, size_t *out_len);

#endif // UTILS_H
