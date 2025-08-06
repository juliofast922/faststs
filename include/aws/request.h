// aws/request.h

#ifndef AWS_REQUEST_H
#define AWS_REQUEST_H

#include "aws/credentials.h"
#include "http.h"
#include "error.h"

#define MAX_EXTRA_HEADERS 8

typedef struct {
    const char *url;
    const char *method;
    const char *service;
    const char *region;
    const char *body;
    const char *signed_headers;  // e.g., "content-type;host;x-amz-date"
    const char *extra_headers[MAX_EXTRA_HEADERS]; // optional extra headers (NULL-terminated)
    int timeout_seconds;
} AwsSignedRequest;

ErrorCode aws_signed_request_execute(const AwsSignedRequest *req, HttpResponse *out_res);

#endif
