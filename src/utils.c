#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

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

int get_env_from_file(const char *filename, const char *key, char *out, size_t out_size) {
    if (!filename || !key || !out || out_size == 0) return 0;

    FILE *file = fopen(filename, "r");
    if (!file) return 0;

    char line[256];
    size_t key_len = strlen(key);

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
            char *value = line + key_len + 1;
            value[strcspn(value, "\r\n")] = '\0';  // Strip newline
            strncpy(out, value, out_size);
            out[out_size - 1] = '\0';
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}