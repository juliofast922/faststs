#ifndef LOGGER_H
#define LOGGER_H

/**
 * @brief Log levels supported by the logger.
 */
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

/**
 * @brief Initializes the logger using environment configuration.
 *
 * Currently reads LOG_LEVEL from the specified .env file.
 *
 * @param env_path Path to the .env file (e.g., ".env")
 */
void logger_init(const char *env_path);

/**
 * @brief Enables optional file logging with time-based rotation.
 *
 * @param enable            1 to enable file logging, 0 to disable
 * @param rotation_seconds  Duration (in seconds) each log file remains active before rotating
 */
void logger_set_file_logging(int enable, int rotation_seconds);

/**
 * @brief Logs a message with structured JSON format.
 *
 * Automatically includes level, timestamp, source file, and line number.
 * Intended to be called via the macros (log_info, log_error, etc).
 *
 * @param level   Log level enum (LOG_INFO, LOG_ERROR, etc.)
 * @param file    Source file name (__FILE__)
 * @param line    Line number (__LINE__)
 * @param fmt     Format string (printf-style)
 * @param ...     Variadic arguments for formatting
 */
void logger_log(LogLevel level, const char *file, int line, const char *fmt, ...);

/* Convenience macros that capture file and line info automatically */
#define log_debug(fmt, ...) logger_log(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  logger_log(LOG_INFO,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  logger_log(LOG_WARN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) logger_log(LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif // LOGGER_H
