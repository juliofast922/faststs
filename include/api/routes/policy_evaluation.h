// api/routes/policy_evaluation.h

#ifndef POLICY_EVALUATION_H
#define POLICY_EVALUATION_H

#include <openssl/ssl.h>

/**
 * @brief TBD.
 *
 * TBD
 *
 * @param ssl     The active SSL connection with the client.
 * @param request The raw HTTP request string (not parsed).
 */
void handle_policy_evaluation(SSL *ssl, const char *request);

#endif // POLICY_EVALUATION_H