// types/timestamp.c

#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include "types/timestamp.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

int timestamp_is_valid_iso8601(const char *input) {
    if (!input) return 0;
    struct tm tm;
    char *ret = strptime(input, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return ret != NULL && *ret == '\0';
}

int timestamp_is_not_expired(const char *input, int skew_seconds) {
    struct tm tm;
    if (!strptime(input, "%Y-%m-%dT%H:%M:%SZ", &tm)) return 0;

    time_t ts = timegm(&tm);
    time_t now = time(NULL);

    return ts > now - skew_seconds && ts < now + skew_seconds;
}
