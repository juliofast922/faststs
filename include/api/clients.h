// api/auth.h

#ifndef CLIENTS_H
#define CLIENTS_H

#include <openssl/x509.h>
#include "error.h"

#define MAX_POLICY_ENTRIES 10

/**
 * @brief Verifies if a client certificate matches a known subject.
 *
 * @param client_cert Pointer to the client's X509 certificate.
 * @return ERROR_NONE if allowed, specific ErrorCode otherwise.
 */
ErrorCode is_client_allowed(X509 *client_cert);

typedef struct {
    char allowed_cn[MAX_POLICY_ENTRIES][128];
    char allowed_ou[MAX_POLICY_ENTRIES][128];
    char allowed_o[MAX_POLICY_ENTRIES][128];
    char allowed_issuer_cn[MAX_POLICY_ENTRIES][128];
    char allowed_san[MAX_POLICY_ENTRIES][256];
    int cn_count, ou_count, o_count, issuer_cn_count, san_count;
} CertPolicyConfig;

/**
 * @brief Load cert policy from env
 * 
 * @param config policy pointer
 */
void load_cert_policy_from_env(CertPolicyConfig *config);

#endif // CLIENTS_H
