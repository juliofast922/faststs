// api/clients.c

#include "api/clients.h"
#include "logger.h"
#include "error.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <stdio.h>

/**
 * List of allowed subject substrings.
 * These are matched against the full DN string (as returned by OpenSSL).
 */
static const char *allowed_subjects[] = {
    "/CN=fastclient",  // exact DN
    "CN=fastclient",   // partial match for safety
    NULL
};

ErrorCode is_client_allowed(X509 *client_cert) {
    if (!client_cert) {
        log_error("Client certificate is missing");
        return ERROR_VALIDATION_FAILED;
    }

    char *subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
    if (!subject) {
        log_error("Failed to extract subject from client certificate");
        return ERROR_VALIDATION_FAILED;
    }

    log_info("Client certificate subject: %s", subject);

    for (int i = 0; allowed_subjects[i] != NULL; i++) {
        if (strstr(subject, allowed_subjects[i]) != NULL) {
            log_info("Client certificate matched allowed subject: %s", allowed_subjects[i]);
            OPENSSL_free(subject);
            return ERROR_NONE;
        }
    }

    log_warn("Client certificate rejected: no match in allowed subjects");
    OPENSSL_free(subject);
    return ERROR_VALIDATION_FAILED;
}
