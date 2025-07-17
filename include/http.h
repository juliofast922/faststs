#ifndef HTTP_H
#define HTTP_H

#include "error.h"
#include <stddef.h>

/**
 * @brief Represents a dynamic HTTP response buffer.
 */
typedef struct {
    char *body;          ///< Response body (heap allocated).
    size_t body_len;     ///< Length of body.
    long status_code;    ///< HTTP response code (e.g. 200, 403).
} HttpResponse;

/**
 * @brief HTTP request configuration.
 */
typedef struct {
    const char *url;
    const char *method;             // "GET", "POST", "PUT", etc.
    const char *body;               // Request body (can be NULL).
    const char **headers;          // NULL-terminated array of header strings.
    size_t body_len;                // Length of body.
    int timeout_seconds;           // Timeout for request.
} HttpRequest;

/**
 * @brief Performs an HTTP or HTTPS request and fills the response.
 *
 * @param req Input HTTP request config.
 * @param res Output: response body, status and length (heap allocated).
 * @return ErrorCode
 */
ErrorCode http_execute(const HttpRequest *req, HttpResponse *res);

/**
 * @brief Frees memory associated with HttpResponse.
 */
void http_response_free(HttpResponse *res);

#endif // HTTP_H
