#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* init_server_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM);
    return ctx;
}

SSL_CTX* init_client_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    return ctx;
}
