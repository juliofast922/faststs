// aws/request.c

#include "aws/request.h"
#include "aws/sigv4.h"
#include "aws/canonical_request.h"
#include "logger.h"
#include "utils.h"
#include <time.h>
#include <string.h>
#include <stdio.h>

ErrorCode aws_signed_request_execute(const AwsSignedRequest *req, HttpResponse *out_res) {
    if (!req || !req->url || !req->method || !req->service || !req->region || !req->body)
        return ERROR_INVALID_ARGUMENT;

    AwsCredentials creds;
    ErrorCode err = load_credentials(&creds);
    if (err != ERROR_NONE)
        return err;

    // === Generate timestamps ===
    char amz_date[17];
    char short_date[9];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);
    strftime(short_date, sizeof(short_date), "%Y%m%d", &tm);

    // === Hash the payload ===
    char payload_hash[65];
    sha256_hex(req->body, payload_hash);

    // === Build canonical headers string ===
    char headers_buf[512];
    snprintf(headers_buf, sizeof(headers_buf),
        "content-type:application/x-www-form-urlencoded\n"
        "host:%s\n"
        "x-amz-date:%s\n", "sts.amazonaws.com", amz_date);

    CanonicalRequest cr = {
        .method = req->method,
        .uri = "/",
        .query_string = "",
        .headers = headers_buf,
        .signed_headers = req->signed_headers,
        .payload_hash = payload_hash
    };

    char canonical_buf[1024];
    err = canonical_request_build(&cr, canonical_buf, sizeof(canonical_buf));
    if (err != ERROR_NONE) return err;

    // === Build authorization header ===
    AuthorizationHeader auth_hdr = {0};
    err = authorization_header_build(
        &creds, amz_date, short_date,
        req->region, req->service,
        canonical_buf, req->signed_headers, &auth_hdr);
    if (err != ERROR_NONE) return err;

    // === Build headers array ===
    char x_amz_date_header[64];
    snprintf(x_amz_date_header, sizeof(x_amz_date_header), "X-Amz-Date: %s", amz_date);

    char auth_header_full[1056];
    snprintf(auth_header_full, sizeof(auth_header_full), "Authorization: %s", auth_hdr.value);

    const char *headers[16] = {
        "Content-Type: application/x-www-form-urlencoded",
        x_amz_date_header,
        auth_header_full,
        NULL
    };

    // Append extra headers if any
    int h = 3;
    for (int i = 0; i < MAX_EXTRA_HEADERS && req->extra_headers[i]; ++i) {
        if (h < 15) headers[h++] = req->extra_headers[i];
    }
    headers[h] = NULL;

    HttpRequest http_req = {
        .url = req->url,
        .method = req->method,
        .headers = headers,
        .body = req->body,
        .body_len = strlen(req->body),
        .timeout_seconds = req->timeout_seconds,
    };

    return http_execute(&http_req, out_res);
}
