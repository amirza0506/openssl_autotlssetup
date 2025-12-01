#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096

void die(const char *msg) {
    perror(msg);
    exit(1);
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *client_cert, const char *client_key, const char *ca_cert) {

    // Load client certificate
    if (SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("ERROR loading client certificate\n");
        exit(1);
    }

    // Load client private key
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("ERROR loading client private key\n");
        exit(1);
    }

    // Verify key matches cert
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Client certificate and key DO NOT match.\n");
        exit(1);
    }

    // Load CA for verifying server certificate
    if (SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("WARNING: could not load CA file. Continuing WITHOUT verification.\n");
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

int main() {

    char server_ip[100];
    int port;

    printf("PQC TLS Client with Authentication\n");
    printf("----------------------------------\n");

    printf("Enter server IP: ");
    scanf("%99s", server_ip);

    printf("Enter server port: ");
    scanf("%d", &port);

    printf("Using client certificate: client.crt\n");
    printf("Using client key       : client.key\n");
    printf("Using CA certificate   : ca.crt\n\n");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = create_context();
    configure_context(ctx, "client.crt", "client.key", "ca.crt");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket()");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0)
        die("inet_pton()");

    printf("Connecting TCP to %s:%d...\n", server_ip, port);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("connect()");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    printf("Starting TLS handshake...\n");

    if (SSL_connect(ssl) <= 0) {
        printf("TLS handshake failed.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("TLS established.\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    printf("Protocol: %s\n\n", SSL_get_version(ssl));

    printf("=== Interactive Mode ===\n");
    printf("Type messages and press ENTER.\n");
    printf("Type 'quit' to close connection.\n\n");

    char input[BUFFER_SIZE];
    char recvbuf[BUFFER_SIZE];

    while (1) {
        printf("client> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        input[strcspn(input, "\n")] = 0;
        if (strcmp(input, "quit") == 0)
            break;

        if (SSL_write(ssl, input, strlen(input)) <= 0) {
            printf("SSL_write failed.\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        int r = SSL_read(ssl, recvbuf, sizeof(recvbuf)-1);
        if (r > 0) {
            recvbuf[r] = 0;
            printf("server> %s\n", recvbuf);
        } else {
            int err = SSL_get_error(ssl, r);
            printf("SSL_read failed: %d\n", err);
            break;
        }
    }

    printf("Closing TLS.\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
