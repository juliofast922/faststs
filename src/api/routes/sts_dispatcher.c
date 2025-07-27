#include "api/routes/sts_dispatcher.h"
#include "aws/aws_error.h"
#include "utils.h"
#include "logger.h"

#include <string.h>
#include <stdio.h>

#define MAX_PARAM_LEN 128

void handle_sts_dispatcher(SSL *ssl, const char *request) {
    // Step 1: Extract request body
    const char *body = strstr(request, "\r\n\r\n");
    if (!body || *(body + 4) == '\0') {
        log_warn("Empty or missing body in request");
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE);
        return;
    }
    body += 4;  // Skip headers

    // Step 2: Match Version
    char version[MAX_PARAM_LEN] = {0};
    if (!match_form_param(body, "Version", version, sizeof(version))) {
        log_warn("Missing Version in request");
        respond_with_aws_error(ssl, AWS_ERROR_MISSING_ACTION);
        return;
    }

    if (strcmp(version, "2011-06-15") != 0) {
        log_warn("Unsupported STS Version: %s", version);
        respond_with_aws_error(ssl, AWS_ERROR_INVALID_PARAMETER_VALUE);
        return;
    }

    // Step 3: Match Action
    char action[MAX_PARAM_LEN] = {0};
    if (!match_form_param(body, "Action", action, sizeof(action))) {
        log_warn("Missing Action parameter");
        respond_with_aws_error(ssl, AWS_ERROR_MISSING_ACTION);
        return;
    }

    log_debug("Action matched: %s", action);

    // Step 4: Dispatch to action handler
    if (strcmp(action, "GetCallerIdentity") == 0) {
        log_info("Handling GetCallerIdentity (stub)");

        // Placeholder response: 200 OK with empty body
        const char *resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/xml\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";

        SSL_write(ssl, resp, strlen(resp));
        return;
    }

    log_warn("Unknown Action: %s", action);
    respond_with_aws_error(ssl, AWS_ERROR_INVALID_ACTION);
}
