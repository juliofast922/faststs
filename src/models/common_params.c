// models/common_params.c

#include "models/common_params.h"
#include "types/timestamp.h"
#include "types/signature_version.h"
#include "types/action.h"
#include "utils.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int validate_common_params(const AWSCommonParams *p) {
    if (!p) return 0;

    log_debug("validate_common_params: action=%d, version=%s, access_key_id=%s, signature=%s, sig_version=%s, timestamp=%s",
        p->action, p->version, p->access_key_id, p->signature, p->signature_version, p->timestamp
    );

    if (p->action == STS_ACTION_INVALID) return 0;
    if (strcmp(p->version, "2011-06-15") != 0) return 0;
    if (!p->access_key_id[0]) return 0;
    if (!timestamp_is_valid_iso8601(p->timestamp)) return 0;
    if (!timestamp_is_not_expired(p->timestamp, 300)) return 0;

    const bool sigv4_in_query = p->signature[0] && p->signature_version[0];

    if (!sigv4_in_query) {
        log_debug("No query signature found — expecting SigV4 Authorization header.");
        // Consider verifying that the handler *actually* checked the Authorization header
    } else {
        if (!signature_version_is_valid(p->signature_version)) return 0;
    }

    return 1;
}

int parse_common_params(const char *body, AWSCommonParams *params) {
    if (!body || !params) return 0;

    char buffer[512];

    memset(params, 0, sizeof(*params));

    if (match_form_param(body, "Version", buffer, sizeof(buffer))) {
        strncpy(params->version, buffer, sizeof(params->version) - 1);
    }

    if (match_form_param(body, "Action", buffer, sizeof(buffer))) {
        params->action = sts_action_from_string(buffer);
    }

    if (match_form_param(body, "AWSAccessKeyId", buffer, sizeof(buffer))) {
        strncpy(params->access_key_id, buffer, sizeof(params->access_key_id) - 1);
    }

    if (match_form_param(body, "Signature", buffer, sizeof(buffer))) {
        strncpy(params->signature, buffer, sizeof(params->signature) - 1);
    }

    if (match_form_param(body, "SignatureMethod", buffer, sizeof(buffer))) {
        strncpy(params->signature_method, buffer, sizeof(params->signature_method) - 1);
    }

    if (match_form_param(body, "SignatureVersion", buffer, sizeof(buffer))) {
        strncpy(params->signature_version, buffer, sizeof(params->signature_version) - 1);
    }

    if (match_form_param(body, "Timestamp", buffer, sizeof(buffer))) {
        strncpy(params->timestamp, buffer, sizeof(params->timestamp) - 1);
    }

    if (match_form_param(body, "SecurityToken", buffer, sizeof(buffer))) {
        strncpy(params->security_token, buffer, sizeof(params->security_token) - 1);
    }

    if (match_form_param(body, "SessionToken", buffer, sizeof(buffer))) {
        strncpy(params->session_token, buffer, sizeof(params->session_token) - 1);
    }

    if (match_form_param(body, "DurationSeconds", buffer, sizeof(buffer))) {
        params->duration_seconds = atoi(buffer); // You can clamp to max if needed
    }

    return 1;
}