#ifndef CLIENTS_H
#define CLIENTS_H

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "error.h"

#define MAX_POLICY_ENTRIES 10
#define MAX_PSK_ENTRIES 8
#define PSK_IDENTITY_MAX_LEN 64

/**
 * @brief Certificate policy configuration loaded from environment variables.
 *
 * Used to enforce mTLS authentication by matching fields like CN, OU, etc.
 */
typedef struct {
    char allowed_cn[MAX_POLICY_ENTRIES][128];
    char allowed_ou[MAX_POLICY_ENTRIES][128];
    char allowed_o[MAX_POLICY_ENTRIES][128];
    char allowed_issuer_cn[MAX_POLICY_ENTRIES][128];
    char allowed_san[MAX_POLICY_ENTRIES][256];
    int cn_count, ou_count, o_count, issuer_cn_count, san_count;
} CertPolicyConfig;

/**
 * @brief Checks if the given X509 client certificate matches the loaded certificate policy.
 *
 * @param client_cert Pointer to the client's X.509 certificate.
 * @return ERROR_NONE if the certificate is accepted, or an appropriate ErrorCode otherwise.
 */
ErrorCode is_client_allowed(X509 *client_cert);

/**
 * @brief Loads allowed certificate fields (CN, OU, etc.) from environment variables into a policy struct.
 *
 * Environment variables:
 * - MTLS_ALLOW_CN
 * - MTLS_ALLOW_OU
 * - MTLS_ALLOW_O
 * - MTLS_ALLOW_ISSUER_CN
 * - MTLS_ALLOW_SAN
 *
 * @param config Pointer to the CertPolicyConfig structure to populate.
 */
void load_cert_policy_from_env(CertPolicyConfig *config);

/**
 * @brief OpenSSL certificate verification callback that enforces custom certificate policy.
 *
 * @param preverify_ok OpenSSL's verification result.
 * @param ctx X509_STORE_CTX containing the certificate to verify.
 * @return 1 if certificate is accepted, 0 otherwise.
 */
int verify_cert_callback(int preverify_ok, X509_STORE_CTX *ctx);

/**
 * @brief Loads allowed PSK identities and associated keys from environment variables.
 *
 * Environment:
 * - PSK_ALLOW_IDENTITY: comma-separated list of allowed identities.
 * - PSK_KEY_<identity>: hex-encoded key for each identity.
 */
void load_psk_policy_from_env(void);

/**
 * @brief OpenSSL PSK server callback used to validate incoming PSK identities and return their keys.
 *
 * @param ssl Pointer to the SSL connection.
 * @param identity Identity string received from the client.
 * @param psk Output buffer where the PSK key will be stored.
 * @param max_psk_len Maximum length of the output buffer.
 * @return Length of the PSK written, or 0 if identity is not allowed.
 */
unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);

/**
 * @brief Checks whether the PSK identity in the SSL session is allowed according to the loaded PSK policy.
 *
 * @param ssl Pointer to the SSL connection.
 * @return ERROR_NONE if allowed, otherwise an error code.
 */
ErrorCode is_psk_client_allowed(SSL *ssl);

/**
 * @brief Initializes the OpenSSL ex_data index used to store the PSK identity in the SSL session.
 *
 * This function must be called once before using `SSL_set_ex_data` or `SSL_get_ex_data` for PSK identity.
 */
void init_psk_identity_index(void);

#endif // CLIENTS_H
