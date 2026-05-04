#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

SSL_CTX* init_server_ctx();
SSL_CTX* init_client_ctx();

#endif
