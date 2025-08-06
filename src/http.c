#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "logger.h"
#include "http.h"

#include <curl/curl.h>

#define MAX_RETRIES 3

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
    if (!req || !req->url || !req->method || !res) {
        log_error("Invalid HTTP input (null ptr)");
        return ERROR_HTTP_INVALID_INPUT;
    }

    // Handle PSK manually via openssl s_client if requested
    if (req->psk_identity && req->psk_key_hex) {
        log_debug("Executing PSK request using openssl s_client");

        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "openssl s_client -psk_identity %s -psk %s -connect %s -quiet",
                 req->psk_identity, req->psk_key_hex, strstr(req->url, "localhost") ? "localhost:8443" : req->url);

        FILE *fp = popen(cmd, "w+");
        if (!fp) {
            log_error("Failed to spawn openssl s_client");
            return ERROR_HTTP_INIT_FAILED;
        }

        const char *req_str =
            "GET /pks HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n\r\n";
        fwrite(req_str, 1, strlen(req_str), fp);
        fflush(fp);

        char buffer[4096];
        size_t total_len = 0;

        res->body = calloc(1, 1);
        while (fgets(buffer, sizeof(buffer), fp)) {
            size_t len = strlen(buffer);
            res->body = realloc(res->body, total_len + len + 1);
            memcpy(res->body + total_len, buffer, len);
            total_len += len;
            res->body[total_len] = '\0';
        }
        res->body_len = total_len;

        pclose(fp);

        // Simple status detection
        if (strstr(res->body, "HTTP/1.1 200 OK")) {
            res->status_code = 200;
            return ERROR_NONE;
        } else {
            res->status_code = 403;
            return ERROR_HTTP_CURL;
        }
    }

    ErrorCode final_err = ERROR_UNKNOWN;

    for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
        log_debug("HTTP attempt %d to %s", attempt, req->url);

        CURL *curl = curl_easy_init();
        if (!curl) {
            log_error("Failed to initialize CURL");
            return ERROR_HTTP_INIT_FAILED;
        }

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

        // Optional TLS settings
        if (req->cert_path && req->key_path) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, req->cert_path);
            curl_easy_setopt(curl, CURLOPT_SSLKEY,  req->key_path);
        }
        
        if (req->ca_path) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, req->ca_path);
        } else {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        for (int i = 0; req->headers && req->headers[i]; ++i) {
            chunk = curl_slist_append(chunk, req->headers[i]);
        }
        if (chunk) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        }

        if (req->body && req->body_len > 0) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req->body_len);
        }

        curl_res = curl_easy_perform(curl);
        if (curl_res == CURLE_OK) {
            long status = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
            res->status_code = status;

            log_info("Received HTTP %ld from %s", status, req->url);

            curl_slist_free_all(chunk);
            curl_easy_cleanup(curl);

            if (status >= 500 && status < 600 && attempt < MAX_RETRIES) {
                log_warn("Server error %ld, retrying (%d/%d)...", status, attempt, MAX_RETRIES);
                http_response_free(res);
                sleep(attempt);  // Exponential backoff
                continue;
            }

            return ERROR_NONE;
        }

        log_error("CURL error: %s (attempt %d/%d)", curl_easy_strerror(curl_res), attempt, MAX_RETRIES);
        final_err = ERROR_HTTP_CURL;

        curl_slist_free_all(chunk);
        curl_easy_cleanup(curl);
        http_response_free(res);

        if (attempt < MAX_RETRIES) {
            sleep(attempt);  // Backoff
        }
    }

    log_error("HTTP request failed after %d attempts", MAX_RETRIES);
    return final_err;
}

void http_response_free(HttpResponse *res) {
    if (res && res->body) {
        free(res->body);
        res->body = NULL;
        res->body_len = 0;
        res->status_code = 0;
    }
}
