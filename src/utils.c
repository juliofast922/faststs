#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "utils.h"

#define MAX_LINE_LEN 512

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

const char *get_env_str(const char *key) {
    return getenv(key);
}

// Helper: trim leading/trailing whitespace (in-place)
static void trim_whitespace(char *str) {
    char *end;

    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

/**
 * Load .env file into process environment (override system vars)
 */
int load_env_file(const char *filename) {
    if (!filename) return 0;

    FILE *file = fopen(filename, "r");
    if (!file) return 0;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), file)) {
        // Skip empty lines and comments
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        if (*start == '#' || *start == '\n' || *start == '\0') continue;

        // Strip newline
        start[strcspn(start, "\r\n")] = '\0';

        char *equal = strchr(start, '=');
        if (!equal) continue;

        *equal = '\0';
        char *key = start;
        char *value = equal + 1;

        trim_whitespace(key);
        trim_whitespace(value);

        if (*key && *value) {
            setenv(key, value, 1);  // override existing
        }
    }

    fclose(file);
    return 1;
}

/**
 * Get env var as a trimmed list split by comma
 */
int get_env_list(const char *key, char *out, size_t max_items, size_t item_len) {
    const char *env_val = getenv(key);
    if (!env_val) return -1;

    char *copy = strdup(env_val);
    if (!copy) return -1;

    size_t count = 0;
    char *token = strtok(copy, ",");

    while (token && count < max_items) {
        trim_whitespace(token);
        char *dest = out + (count * item_len);
        strncpy(dest, token, item_len - 1);
        dest[item_len - 1] = '\0';
        count++;
        token = strtok(NULL, ",");
    }

    free(copy);
    return (int)count;
}

int match_form_param(const char *body, const char *key, char *out, size_t out_size) {
    if (!body || !key || !out || out_size == 0) return 0;
    size_t key_len = strlen(key);

    const char *start = strstr(body, key);
    if (!start) return 0;

    start += key_len;
    if (*start != '=') return 0;
    start++;

    const char *end = strchr(start, '&');
    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len >= out_size) return 0;

    strncpy(out, start, len);
    out[len] = '\0';
    return 1;
}

int hexstr_to_bytes(const char *hex, unsigned char *out, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;

    *out_len = len / 2;
    for (size_t i = 0; i < *out_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &out[i]) != 1) return -1;
    }
    return 0;
}

int match_header_param(const char *request, const char *key, char *out, size_t out_size) {
    // Very naive parsing for "Key: Value\r\n" style headers
    const char *start = strstr(request, key);
    if (!start) return 0;

    const char *colon = strchr(start, ':');
    if (!colon || colon[1] != ' ') return 0;

    const char *value_start = colon + 2;
    const char *end = strstr(value_start, "\r\n");
    if (!end) return 0;

    size_t len = end - value_start;
    if (len >= out_size) return 0;

    strncpy(out, value_start, len);
    out[len] = '\0';
    return 1;
}