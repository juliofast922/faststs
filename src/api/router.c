// api/router.c

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "api/router.h"
#include "api/clients.h"
#include "logger.h"
#include "error.h"

#define MAX_ROUTES 32
#define METHOD_LEN 8
#define PATH_LEN 64

typedef struct {
    char method[METHOD_LEN];
    char path[PATH_LEN];
    route_handler_t handler;
    AuthPolicy auth;
} Route;

static Route route_table[MAX_ROUTES];
static int route_count = 0;

void register_route(const char *method, const char *path, route_handler_t handler, AuthPolicy auth) {
    if (route_count >= MAX_ROUTES) {
        log_error("Route table full; cannot register '%s %s'", method, path);
        return;
    }

    strncpy(route_table[route_count].method, method, METHOD_LEN - 1);
    strncpy(route_table[route_count].path, path, PATH_LEN - 1);
    route_table[route_count].handler = handler;
    route_table[route_count].auth = auth;
    route_count++;

    log_debug("Registered route: %s %s (auth=%d)", method, path, auth);
}

// Simple parser to extract method and path from request line
static int parse_request_line(const char *request, char *method_out, char *path_out) {
    return sscanf(request, "%7s %63s", method_out, path_out);
}

void handle_request(SSL *ssl, const char *raw_request) {
    char method[METHOD_LEN] = {0};
    char path[PATH_LEN] = {0};

    if (parse_request_line(raw_request, method, path) != 2) {
        log_warn("Malformed request line");
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        SSL_write(ssl, resp, strlen(resp));
        return;
    }

    log_debug("Parsed request: method=%s, path=%s", method, path);

    for (int i = 0; i < route_count; i++) {
        if (strcmp(method, route_table[i].method) == 0 &&
            strcmp(path, route_table[i].path) == 0) {

            AuthPolicy auth = route_table[i].auth;
            ErrorCode auth_result = ERROR_NONE;

            switch (auth) {
                case AUTH_NONE:
                    auth_result = ERROR_NONE;
                    break;

                case AUTH_MTLS: {
                    int *authorized_flag = SSL_get_ex_data(ssl, SSL_EX_AUTHORIZED_IDX);
                
                    if (authorized_flag && *authorized_flag == 1) {
                        log_debug("Client already authorized");
                        auth_result = ERROR_NONE;
                    } else {
                        X509 *client_cert = SSL_get_peer_certificate(ssl);
                        auth_result = is_client_allowed(client_cert);
                        if (client_cert) X509_free(client_cert);
                
                        if (auth_result == ERROR_NONE) {
                            int *flag = malloc(sizeof(int));
                            if (flag) {
                                *flag = 1;
                                SSL_set_ex_data(ssl, SSL_EX_AUTHORIZED_IDX, flag);
                                log_debug("Client authorized and cached for session");
                            } else {
                                log_warn("Failed to allocate memory for auth flag");
                            }
                        }
                    }
                    break;
                }
                
                case AUTH_PSK: {
                    auth_result = is_psk_client_allowed(ssl);
                    break;
                }

                default:
                    log_error("Unknown auth policy for route %s %s", method, path);
                    auth_result = ERROR_VALIDATION_FAILED;
            }

            if (auth_result != ERROR_NONE) {
                log_warn("Unauthorized client: %s", error_to_string(auth_result));
                const char *resp = "HTTP/1.1 403 Forbidden\r\n\r\n";
                SSL_write(ssl, resp, strlen(resp));
                return;
            }

            log_debug("Dispatching to handler: %s %s", method, path);
            route_table[i].handler(ssl, raw_request);
            log_info("Successfully responded to: %s %s", method, path);
            return;
        }
    }

    log_warn("No matching route for %s %s", method, path);
    const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n";
    SSL_write(ssl, resp, strlen(resp));
}