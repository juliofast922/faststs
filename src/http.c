#include "http.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    HttpResponse *res = (HttpResponse *)userp;

    char *new_ptr = realloc(res->body, res->body_len + total + 1);
    if (!new_ptr) return 0;

    res->body = new_ptr;
    memcpy(&(res->body[res->body_len]), contents, total);
    res->body_len += total;
    res->body[res->body_len] = 0;

    return total;
}

ErrorCode http_execute(const HttpRequest *req, HttpResponse *res) {
    if (!req || !req->url || !req->method || !res)
        return ERROR_HTTP_INVALID_INPUT;

    CURL *curl = curl_easy_init();
    if (!curl) return ERROR_HTTP_INIT_FAILED;

    CURLcode curl_res;
    struct curl_slist *chunk = NULL;

    res->body = NULL;
    res->body_len = 0;
    res->status_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, res);

    if (req->timeout_seconds > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, req->timeout_seconds);
    }

    // Headers
    for (int i = 0; req->headers && req->headers[i]; ++i) {
        chunk = curl_slist_append(chunk, req->headers[i]);
    }
    if (chunk) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
    }

    // Body
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req->body_len);
    }

    // Perform
    curl_res = curl_easy_perform(curl);
    if (curl_res != CURLE_OK) {
        fprintf(stderr, "[http] CURL error: %s\n", curl_easy_strerror(curl_res));
        curl_slist_free_all(chunk);
        curl_easy_cleanup(curl);
        return ERROR_HTTP_CURL;
    }

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    res->status_code = status;

    curl_slist_free_all(chunk);
    curl_easy_cleanup(curl);

    return ERROR_NONE;
}

void http_response_free(HttpResponse *res) {
    if (res && res->body) {
        free(res->body);
        res->body = NULL;
        res->body_len = 0;
        res->status_code = 0;
    }
}
