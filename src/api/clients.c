// src/api/clients.c

#include "api/clients.h"
#include "logger.h"
#include "error.h"
#include "utils.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl3.h>
#include <string.h>
#include <stdio.h>

static int psk_identity_index = -1;

void init_psk_identity_index() {
    if (psk_identity_index == -1) {
        psk_identity_index = SSL_get_ex_new_index(0, "psk_identity", NULL, NULL, NULL);
    }
}

typedef struct {
    char identity[PSK_IDENTITY_MAX_LEN];
    unsigned char key[32];  // Máximo 256 bits
    size_t key_len;
} PskEntry;

static PskEntry allowed_psks[MAX_PSK_ENTRIES];
static int allowed_psk_count = 0;

void load_cert_policy_from_env(CertPolicyConfig *config) {
    config->cn_count = get_env_list("MTLS_ALLOW_CN", (char *)config->allowed_cn, MAX_POLICY_ENTRIES, sizeof(config->allowed_cn[0]));
    config->ou_count = get_env_list("MTLS_ALLOW_OU", (char *)config->allowed_ou, MAX_POLICY_ENTRIES, sizeof(config->allowed_ou[0]));
    config->o_count  = get_env_list("MTLS_ALLOW_O",  (char *)config->allowed_o,  MAX_POLICY_ENTRIES, sizeof(config->allowed_o[0]));
    config->issuer_cn_count = get_env_list("MTLS_ALLOW_ISSUER_CN", (char *)config->allowed_issuer_cn, MAX_POLICY_ENTRIES, sizeof(config->allowed_issuer_cn[0]));
    config->san_count = get_env_list("MTLS_ALLOW_SAN", (char *)config->allowed_san, MAX_POLICY_ENTRIES, sizeof(config->allowed_san[0]));
}

void load_psk_policy_from_env(void) {
    allowed_psk_count = 0;

    char identities[MAX_PSK_ENTRIES][PSK_IDENTITY_MAX_LEN];
    int count = get_env_list("PSK_ALLOW_IDENTITY", (char *)identities, MAX_PSK_ENTRIES, sizeof(identities[0]));

    if (count <= 0) {
        log_warn("PSK_ALLOW_IDENTITY not set or empty");
        return;
    }

    for (int i = 0; i < count; ++i) {
        strncpy(allowed_psks[allowed_psk_count].identity, identities[i], PSK_IDENTITY_MAX_LEN - 1);
        allowed_psks[allowed_psk_count].identity[PSK_IDENTITY_MAX_LEN - 1] = '\0';

        char env_key[256];
        snprintf(env_key, sizeof(env_key), "PSK_KEY_%s", identities[i]);

        const char *key_hex = get_env_str(env_key);
        if (!key_hex) {
            log_warn("Missing %s in environment", env_key);
            continue;
        }

        if (hexstr_to_bytes(key_hex, allowed_psks[allowed_psk_count].key, &allowed_psks[allowed_psk_count].key_len) != 0) {
            log_warn("Invalid hex key for identity: %s", identities[i]);
            continue;
        }

        log_debug("Loaded PSK identity: %s with key (hex): %s", identities[i], key_hex);
        allowed_psk_count++;
    }
}


static int match_any(const char *value, char list[][128], int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(value, list[i]) == 0) return 1;
    }
    return 0;
}

static int match_any_san(const char *value, char list[][256], int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(value, list[i]) == 0) return 1;
    }
    return 0;
}

ErrorCode is_client_allowed(X509 *client_cert) {
    if (!client_cert) {
        log_error("Client certificate is missing");
        return ERROR_VALIDATION_FAILED;
    }

    CertPolicyConfig policy = {0};
    load_cert_policy_from_env(&policy);

    X509_NAME *subject = X509_get_subject_name(client_cert);
    char buf[256];

    // Common Name (CN)
    if (policy.cn_count > 0 &&
        X509_NAME_get_text_by_NID(subject, NID_commonName, buf, sizeof(buf)) > 0 &&
        !match_any(buf, policy.allowed_cn, policy.cn_count)) {
        log_warn("CN '%s' not in allowed list", buf);
        return ERROR_VALIDATION_FAILED;
    }

    // Organization (O)
    if (policy.o_count > 0 &&
        X509_NAME_get_text_by_NID(subject, NID_organizationName, buf, sizeof(buf)) > 0 &&
        !match_any(buf, policy.allowed_o, policy.o_count)) {
        log_warn("O '%s' not in allowed list", buf);
        return ERROR_VALIDATION_FAILED;
    }

    // Organizational Unit (OU)
    if (policy.ou_count > 0 &&
        X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, buf, sizeof(buf)) > 0 &&
        !match_any(buf, policy.allowed_ou, policy.ou_count)) {
        log_warn("OU '%s' not in allowed list", buf);
        return ERROR_VALIDATION_FAILED;
    }

    // Issuer CN
    if (policy.issuer_cn_count > 0) {
        X509_NAME *issuer = X509_get_issuer_name(client_cert);
        if (X509_NAME_get_text_by_NID(issuer, NID_commonName, buf, sizeof(buf)) > 0 &&
            !match_any(buf, policy.allowed_issuer_cn, policy.issuer_cn_count)) {
            log_warn("Issuer CN '%s' not in allowed list", buf);
            return ERROR_VALIDATION_FAILED;
        }
    }

    // Subject Alternative Name (SAN)
    if (policy.san_count > 0) {
        GENERAL_NAMES *san_list = X509_get_ext_d2i(client_cert, NID_subject_alt_name, NULL, NULL);
        if (!san_list) {
            log_warn("No SAN section found");
            return ERROR_VALIDATION_FAILED;
        }

        for (int i = 0; i < sk_GENERAL_NAME_num(san_list); i++) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_list, i);
            if (name->type == GEN_DNS) {
                const char *dns_name = (const char *)ASN1_STRING_get0_data(name->d.dNSName);
                if (dns_name && match_any_san(dns_name, policy.allowed_san, policy.san_count)) {
                    GENERAL_NAMES_free(san_list);
                    log_debug("Client certificate SAN matched");
                    return ERROR_NONE;
                }
            }
        }

        GENERAL_NAMES_free(san_list);
        log_warn("No SAN matched allowed list");
        return ERROR_VALIDATION_FAILED;
    }

    log_debug("Client certificate accepted based on policy");
    return ERROR_NONE;
}

// --- New callback for use in SSL_CTX_set_verify ---
int verify_cert_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        return 0;  // Let OpenSSL reject it first
    }

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) {
        log_error("verify_cert_callback: Failed to get current certificate");
        return 0;
    }

    ErrorCode result = is_client_allowed(cert);
    return result == ERROR_NONE ? 1 : 0;
}

unsigned int psk_server_callback(SSL *ssl, const char *identity,
    unsigned char *psk, unsigned int max_psk_len) {
    log_debug("psk_server_callback invoked");

    if (!identity) {
    log_warn("PSK identity is NULL");
    return 0;
    }

    log_debug("Received PSK identity: %s", identity);

    for (int i = 0; i < allowed_psk_count; ++i) {
    if (strcmp(identity, allowed_psks[i].identity) == 0) {
    if (allowed_psks[i].key_len > max_psk_len) return 0;
    memcpy(psk, allowed_psks[i].key, allowed_psks[i].key_len);

    // Store identity in SSL object
    SSL_set_ex_data(ssl, psk_identity_index, strdup(identity));

    return (unsigned int)allowed_psks[i].key_len;
    }
    }

    log_warn("PSK identity not allowed: %s", identity);
    return 0;
}

ErrorCode is_psk_client_allowed(SSL *ssl) {
    load_psk_policy_from_env();

    const char *identity = SSL_get_ex_data(ssl, psk_identity_index);
    if (!identity) {
        log_warn("No PSK identity provided");
        return ERROR_VALIDATION_FAILED;
    }

    log_debug("Client PSK identity: %s", identity);

    for (int i = 0; i < allowed_psk_count; ++i) {
        if (strcmp(identity, allowed_psks[i].identity) == 0) {
            log_debug("PSK identity '%s' accepted", identity);
            return ERROR_NONE;
        }
    }    

    log_warn("PSK identity not in allowlist: %s", identity);
    return ERROR_VALIDATION_FAILED;
}