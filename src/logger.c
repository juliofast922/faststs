#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "logger.h"
#include "utils.h"

static LogLevel current_level = LOG_INFO;
static int log_to_file = 0;
static int rotation_period = 0;
static FILE *log_file = NULL;
static time_t rotation_start = 0;

/**
 * @brief Converts a LogLevel enum to its string representation.
 *
 * @param level The enum value.
 * @return const char* String representation of the level.
 */
static const char *level_to_string(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        default:        return "UNKNOWN";
    }
}

/**
 * @brief Returns the log level string with ANSI color for console output.
 *
 * Only applies color to the level name. Used for stdout only.
 *
 * @param level The LogLevel enum.
 * @return const char* Colored level name (static buffer).
 */
static const char *colored_level(LogLevel level) {
    static char buf[16];
    const char *name = level_to_string(level);
    const char *color;

    switch (level) {
        case LOG_ERROR: color = "\033[31m"; break; // red
        case LOG_WARN:  color = "\033[33m"; break; // yellow
        case LOG_DEBUG: color = "\033[34m"; break; // blue
        default:        color = ""; break;         // no color for INFO/UNKNOWN
    }

    if (color[0] == '\0') {
        snprintf(buf, sizeof(buf), "%s", name);
    } else {
        snprintf(buf, sizeof(buf), "%s%s\033[0m", color, name); // reset after color
    }

    return buf;
}

static LogLevel string_to_level(const char *lvl) {
    if (strcmp(lvl, "DEBUG") == 0) return LOG_DEBUG;
    if (strcmp(lvl, "INFO") == 0)  return LOG_INFO;
    if (strcmp(lvl, "WARN") == 0)  return LOG_WARN;
    if (strcmp(lvl, "ERROR") == 0) return LOG_ERROR;
    return LOG_INFO;
}

void logger_init(const char *env_path) {
    char buffer[64];

    if (env_path) {
        if (get_env_from_file(env_path, "LOG_LEVEL", buffer, sizeof(buffer))) {
            current_level = string_to_level(buffer);
            return;
        }
    }

    const char *env = get_env_str("LOG_LEVEL");
    if (env) {
        current_level = string_to_level(env);
    }
}

void logger_set_file_logging(int enable, int rotate_sec) {
    log_to_file = enable;
    rotation_period = rotate_sec;
    rotation_start = time(NULL);
}

/**
 * @brief Ensures a log file is open if file logging is enabled.
 *
 * Creates the logs/ directory if needed and rotates file when time expires.
 */
static void open_log_file_if_needed() {
    if (!log_to_file) return;

    time_t now = time(NULL);
    if (log_file && difftime(now, rotation_start) < rotation_period) return;

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }

    // Create logs/ directory if it doesn't exist
    struct stat st = {0};
    if (stat("logs", &st) == -1) {
        mkdir("logs", 0777);
    }

    // Create new log file with timestamp
    rotation_start = now;
    struct tm *tm_info = localtime(&now);
    char filename[64];
    strftime(filename, sizeof(filename), "logs/log_%Y%m%d_%H%M%S.json", tm_info);
    log_file = fopen(filename, "a");
}

void logger_log(LogLevel level, const char *file, int line, const char *fmt, ...) {
    if (level < current_level) return;

    // Get current time in ISO 8601 UTC format
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    // Format the message
    char message[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // Print to stdout in JSON
    fprintf(stdout,
        "{\"level\":\"%s\",\"timestamp\":\"%s\",\"message\":\"%s\",\"source\":\"%s:%d\"}\n",
        colored_level(level), timestamp, message, file, line
    );   

    // Write to file if enabled
    if (log_to_file) {
        open_log_file_if_needed();
        if (log_file) {
            fprintf(log_file,
                "{\"level\":\"%s\",\"timestamp\":\"%s\",\"message\":\"%s\",\"source\":\"%s:%d\"}\n",
                level_to_string(level), timestamp, message, file, line
            );
            fflush(log_file);
        }
    }
}
