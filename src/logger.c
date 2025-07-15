#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "logger.h"

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
 * @brief Converts a string (from .env) to a LogLevel enum.
 *
 * @param lvl The string to convert.
 * @return LogLevel Corresponding enum value.
 */
static LogLevel string_to_level(const char *lvl) {
    if (strcmp(lvl, "DEBUG") == 0) return LOG_DEBUG;
    if (strcmp(lvl, "INFO") == 0)  return LOG_INFO;
    if (strcmp(lvl, "WARN") == 0)  return LOG_WARN;
    if (strcmp(lvl, "ERROR") == 0) return LOG_ERROR;
    return LOG_INFO;
}

/**
 * @brief Initializes the logger with config from a .env file.
 *
 * Currently only supports reading LOG_LEVEL.
 *
 * @param env_path Path to the .env file.
 */
void logger_init(const char *env_path) {
    FILE *env = fopen(env_path, "r");
    if (!env) return;

    char line[256];
    while (fgets(line, sizeof(line), env)) {
        if (strncmp(line, "LOG_LEVEL=", 10) == 0) {
            char *lvl = line + 10;
            lvl[strcspn(lvl, "\r\n")] = 0;  // Remove newline
            current_level = string_to_level(lvl);
        }
    }
    fclose(env);
}

/**
 * @brief Enables file logging with rotation.
 *
 * When enabled, logs are written to logs/ and rotated after `rotate_sec`.
 *
 * @param enable       1 to enable file logging, 0 to disable.
 * @param rotate_sec   Time window in seconds for log file rotation.
 */
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

/**
 * @brief Logs a message with level, timestamp, source location, and JSON formatting.
 *
 * If file logging is enabled, also writes to a rotated log file.
 *
 * @param level LogLevel enum (DEBUG, INFO, etc.)
 * @param file  Source file name (from __FILE__)
 * @param line  Line number (from __LINE__)
 * @param fmt   Format string for the message
 * @param ...   Variadic args for formatting
 */
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
        level_to_string(level), timestamp, message, file, line
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
