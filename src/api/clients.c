#include "api/clients.h"
#include "logger.h"
#include "error.h"
#include "utils.h"

#include <openssl/x509.h>
#include <openssl/err.h>
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
    unsigned char key[32];
    size_t key_len;
} PskEntry;

static PskEntry allowed_psks[MAX_PSK_ENTRIES];
static int allowed_psk_count = 0;
static int psk_policy_enabled = 0;

void load_cert_policy_from_env(CertPolicyConfig *config) {
    config->cn_count        = get_env_list("MTLS_ALLOW_CN", (char *)config->allowed_cn, MAX_POLICY_ENTRIES, sizeof(config->allowed_cn[0]));
    config->ou_count        = get_env_list("MTLS_ALLOW_OU", (char *)config->allowed_ou, MAX_POLICY_ENTRIES, sizeof(config->allowed_ou[0]));
    config->o_count         = get_env_list("MTLS_ALLOW_O", (char *)config->allowed_o, MAX_POLICY_ENTRIES, sizeof(config->allowed_o[0]));
    config->issuer_cn_count = get_env_list("MTLS_ALLOW_ISSUER_CN", (char *)config->allowed_issuer_cn, MAX_POLICY_ENTRIES, sizeof(config->allowed_issuer_cn[0]));
    config->san_count       = get_env_list("MTLS_ALLOW_SAN", (char *)config->allowed_san, MAX_POLICY_ENTRIES, sizeof(config->allowed_san[0]));
}

void load_psk_policy_from_env(void) {
    allowed_psk_count = 0;
    psk_policy_enabled = 0;

    char identities[MAX_PSK_ENTRIES][PSK_IDENTITY_MAX_LEN];
    int count = get_env_list("PSK_ALLOW_IDENTITY", (char *)identities, MAX_PSK_ENTRIES, sizeof(identities[0]));

    if (count <= 0) {
        log_warn("PSK_ALLOW_IDENTITY not set or empty — all PSK identities will be allowed");
        return;
    }

    psk_policy_enabled = 1;

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

static int match_any_generic(const char *value, char *list, int count, size_t item_len) {
    for (int i = 0; i < count; i++) {
        if (strcmp(value, list + i * item_len) == 0) return 1;
    }
    return 0;
}

static int check_nid_field_match(X509_NAME *subject, int nid, char *allowed_list, int count, size_t item_len, const char *label) {
    char buf[256] = {0};
    if (count == 0) return 1;
    if (X509_NAME_get_text_by_NID(subject, nid, buf, sizeof(buf)) <= 0) return 1;
    if (!match_any_generic(buf, allowed_list, count, item_len)) {
        log_warn("%s '%s' not in allowed list", label, buf);
        return 0;
    }
    return 1;
}

static int match_san(X509 *cert, CertPolicyConfig *policy) {
    GENERAL_NAMES *san_list = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!san_list) {
        log_warn("No SAN section found");
        return 0;
    }

    int matched = 0;
    for (int i = 0; i < sk_GENERAL_NAME_num(san_list); i++) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_list, i);
        if (name->type == GEN_DNS) {
            const char *dns_name = (const char *)ASN1_STRING_get0_data(name->d.dNSName);
            if (dns_name && match_any_generic(dns_name, (char *)policy->allowed_san, policy->san_count, sizeof(policy->allowed_san[0]))) {
                matched = 1;
                break;
            }
        }
    }
    GENERAL_NAMES_free(san_list);
    return matched;
}

ErrorCode is_client_allowed(X509 *client_cert) {
    if (!client_cert) {
        log_error("Client certificate is missing");
        return ERROR_VALIDATION_FAILED;
    }

    CertPolicyConfig policy = {0};
    load_cert_policy_from_env(&policy);

    X509_NAME *subject = X509_get_subject_name(client_cert);
    X509_NAME *issuer  = X509_get_issuer_name(client_cert);

    char subject_buf[256] = {0};
    char issuer_buf[256] = {0};

    X509_NAME_get_text_by_NID(subject, NID_commonName, subject_buf, sizeof(subject_buf));
    X509_NAME_get_text_by_NID(issuer,  NID_commonName, issuer_buf,  sizeof(issuer_buf));

    log_debug("Parsed Subject CN: '%s'", subject_buf);
    log_debug("Parsed Issuer CN: '%s'", issuer_buf);

    if ((policy.cn_count > 0 && !match_any_generic(subject_buf, (char *)policy.allowed_cn, policy.cn_count, sizeof(policy.allowed_cn[0]))) ||
        (policy.issuer_cn_count > 0 && !match_any_generic(issuer_buf, (char *)policy.allowed_issuer_cn, policy.issuer_cn_count, sizeof(policy.allowed_issuer_cn[0]))) ||
        !check_nid_field_match(subject, NID_organizationName, (char *)policy.allowed_o, policy.o_count, sizeof(policy.allowed_o[0]), "O") ||
        !check_nid_field_match(subject, NID_organizationalUnitName, (char *)policy.allowed_ou, policy.ou_count, sizeof(policy.allowed_ou[0]), "OU") ||
        (policy.san_count > 0 && !match_san(client_cert, &policy))) {
        return ERROR_VALIDATION_FAILED;
    }

    log_debug("Client certificate accepted based on policy");
    return ERROR_NONE;
}

int verify_cert_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) return 0;

    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (depth != 0) return 1;

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) {
        log_error("verify_cert_callback: Failed to get current certificate");
        return 0;
    }

    return is_client_allowed(cert) == ERROR_NONE ? 1 : 0;
}

unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
    log_debug("psk_server_callback invoked");

    if (!identity) {
        log_warn("PSK identity is NULL");
        return 0;
    }

    log_debug("Received PSK identity: %s", identity);

    const char *psk_hex = NULL;
    size_t key_len = 0;

    if (!psk_policy_enabled) {
        psk_hex = get_env_str("PSK_KEY_DEFAULT");
        if (!psk_hex) psk_hex = "68656c6c6f736563726574"; // fallback default
    } else {
        for (int i = 0; i < allowed_psk_count; ++i) {
            if (strcmp(identity, allowed_psks[i].identity) == 0) {
                if (allowed_psks[i].key_len > max_psk_len) return 0;
                memcpy(psk, allowed_psks[i].key, allowed_psks[i].key_len);
                SSL_set_ex_data(ssl, psk_identity_index, strdup(identity));
                return (unsigned int)allowed_psks[i].key_len;
            }
        }
        log_warn("PSK identity not allowed: %s", identity);
        return 0;
    }

    if (hexstr_to_bytes(psk_hex, psk, &key_len) != 0 || key_len > max_psk_len) {
        log_error("PSK hex parsing failed for identity '%s'", identity);
        return 0;
    }

    log_debug("Fallback mode: accepting identity '%s' with PSK", identity);
    SSL_set_ex_data(ssl, psk_identity_index, strdup(identity));
    return (unsigned int)key_len;
}

ErrorCode is_psk_client_allowed(SSL *ssl) {
    const char *identity = SSL_get_ex_data(ssl, psk_identity_index);
    if (!identity) {
        log_warn("No PSK identity provided");
        return ERROR_VALIDATION_FAILED;
    }

    if (!psk_policy_enabled) {
        log_debug("PSK identity '%s' accepted (fallback mode)", identity);
        return ERROR_NONE;
    }

    for (int i = 0; i < allowed_psk_count; ++i) {
        if (strcmp(identity, allowed_psks[i].identity) == 0) {
            log_debug("PSK identity '%s' accepted", identity);
            return ERROR_NONE;
        }
    }

    log_warn("PSK identity not in allowlist: %s", identity);
    return ERROR_VALIDATION_FAILED;
}
