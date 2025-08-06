#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "aws/aws_error.h"
#include "aws/credentials.h"
#include "error.h"
#include "logger.h"
#include "aws/sigv4.h"

// === Helpers ===

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out_hex) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(out_hex + (i * 2), "%02x", bytes[i]);
    }
    out_hex[len * 2] = '\0';
}

void sha256_hex(const char *data, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, strlen(data), hash);
    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, out_hex);
}

void hmac_sha256(const unsigned char *key, int key_len, const char *msg, unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, key_len, (const unsigned char *)msg, strlen(msg), out, &len);
}

// === Key Derivation ===

static void derive_signing_key(
    const char *secret_key, const char *date, const char *region,
    const char *service, unsigned char *out_key
) {
    unsigned char k_date[SHA256_DIGEST_LENGTH];
    unsigned char k_region[SHA256_DIGEST_LENGTH];
    unsigned char k_service[SHA256_DIGEST_LENGTH];
    unsigned char k_signing[SHA256_DIGEST_LENGTH];

    char k_secret[128];
    snprintf(k_secret, sizeof(k_secret), "AWS4%s", secret_key);

    hmac_sha256((unsigned char *)k_secret, strlen(k_secret), date, k_date);
    hmac_sha256(k_date, SHA256_DIGEST_LENGTH, region, k_region);
    hmac_sha256(k_region, SHA256_DIGEST_LENGTH, service, k_service);
    hmac_sha256(k_service, SHA256_DIGEST_LENGTH, "aws4_request", k_signing);

    memcpy(out_key, k_signing, SHA256_DIGEST_LENGTH);
}

// === Main Function ===

ErrorCode authorization_header_build(
    const AwsCredentials *creds,
    const char *amz_date,
    const char *date,
    const char *region,
    const char *service,
    const char *canonical_request,
    AuthorizationHeader *out_header
) {
    if (!creds || !amz_date || !date || !region || !service || !canonical_request || !out_header)
        return ERROR_SIGV4_INVALID_INPUT;

    log_debug("CanonicalRequest:\n%s", canonical_request);

    // Step 1: Hash the canonical request
    char hashed_request[65];
    sha256_hex(canonical_request, hashed_request);
    log_debug("Hashed CanonicalRequest: %s", hashed_request);

    // Step 2: Build the string to sign
    char scope[128];
    snprintf(scope, sizeof(scope), "%s/%s/%s/aws4_request", date, region, service);

    char string_to_sign[1024];
    snprintf(string_to_sign, sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n%s\n%s\n%s",
             amz_date, scope, hashed_request);
    log_debug("StringToSign:\n%s", string_to_sign);

    // Step 3: Derive the signing key
    unsigned char signing_key[SHA256_DIGEST_LENGTH];
    derive_signing_key(creds->secret_key, date, region, service, signing_key);

    // Step 4: Sign the string to sign
    unsigned char signature_bin[SHA256_DIGEST_LENGTH];
    hmac_sha256(signing_key, SHA256_DIGEST_LENGTH, string_to_sign, signature_bin);

    char signature_hex[65];
    bytes_to_hex(signature_bin, SHA256_DIGEST_LENGTH, signature_hex);
    log_debug("Signature: %s", signature_hex);

    strncpy(out_header->signature, signature_hex, sizeof(out_header->signature) - 1);
    out_header->signature[sizeof(out_header->signature) - 1] = '\0';

    // Step 5: Build the authorization header
    snprintf(out_header->value, sizeof(out_header->value),
             "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;x-amz-date, Signature=%s",
             creds->access_key, scope, signature_hex);

    log_debug("AuthorizationHeader: %s", out_header->value);
    return ERROR_NONE;
}

const char *authorization_header_str(const AuthorizationHeader *header) {
    return header ? header->value : "";
}

ErrorCode validate_authorization_credentials(const AuthorizationHeader *header) {
    if (!header) return ERROR_SIGV4_INVALID_INPUT;

    AwsCredentials creds;
    ErrorCode err = load_credentials(&creds);
    if (err != ERROR_NONE)
        return ERROR_CREDENTIALS_NOT_FOUND;

    if (strcmp(header->access_key_id, creds.access_key) != 0)
        return ERROR_INVALID_CLIENT_TOKEN_ID;

    return ERROR_NONE;
}

static int starts_with(const char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

ErrorCode authorization_header_parse(const char *header_str, AuthorizationHeader *out_header) {
    if (!header_str || !out_header) return ERROR_SIGV4_INVALID_INPUT;

    memset(out_header, 0, sizeof(*out_header));
    strncpy(out_header->value, header_str, sizeof(out_header->value) - 1);

    if (!starts_with(header_str, "AWS4-HMAC-SHA256 ")) {
        return ERROR_SIGV4_INVALID_FORMAT;
    }

    const char *ptr = header_str + strlen("AWS4-HMAC-SHA256 ");

    char *header_copy = strdup(ptr);
    if (!header_copy) return ERROR_MEMORY_ALLOCATION;

    char *token = strtok(header_copy, ",");
    while (token) {
        while (*token == ' ') token++;

        if (starts_with(token, "Credential=")) {
            const char *cred_val = token + strlen("Credential=");
            char *slash = strchr(cred_val, '/');
            if (!slash) {
                free(header_copy);
                return ERROR_SIGV4_INVALID_FORMAT;
            }
            size_t akid_len = slash - cred_val;
            if (akid_len >= sizeof(out_header->access_key_id)) {
                free(header_copy);
                return ERROR_SIGV4_INVALID_FORMAT;
            }
            strncpy(out_header->access_key_id, cred_val, akid_len);
            out_header->access_key_id[akid_len] = '\0';
            strncpy(out_header->scope, slash + 1, sizeof(out_header->scope) - 1);

        } else if (starts_with(token, "SignedHeaders=")) {
            strncpy(out_header->signed_headers,
                    token + strlen("SignedHeaders="),
                    sizeof(out_header->signed_headers) - 1);
        } else if (starts_with(token, "Signature=")) {
            strncpy(out_header->signature,
                    token + strlen("Signature="),
                    sizeof(out_header->signature) - 1);
        }

        token = strtok(NULL, ",");
    }

    free(header_copy);

    if (!out_header->access_key_id[0] || !out_header->signature[0]) {
        return ERROR_SIGV4_INVALID_FORMAT;
    }

    return ERROR_NONE;
}