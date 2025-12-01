#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 4096

void die(const char *msg) {
    perror(msg);
    exit(1);
}

SSL_CTX *create_tls_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new");

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1)
        die("load CA failed");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0)
        die("Loading client.crt failed");

    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0)
        die("Loading client.key failed");

    return ctx;
}

int main() {
    char ip[100], port_str[20];
    int port;

    printf("PQC TLS Client (Persistent)\n");
    printf("Server IP: ");
    scanf("%99s", ip);

    printf("Server Port: ");
    scanf("%19s", port_str);
    port = atoi(port_str);

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = create_tls_ctx();
    SSL *ssl;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        die("inet_pton");

    printf("Connecting to %s:%d...\n", ip, port);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("connect");

    printf("Connected. Starting TLS handshake...\n");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        die("TLS handshake failed");
    }

    printf("\n=== TLS ESTABLISHED ===\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    printf("Protocol: %s\n", SSL_get_version(ssl));
    printf("========================\n\n");

    char sendbuf[BUF_SIZE], recvbuf[BUF_SIZE];

    // Flush newline from stdin
    getchar();

    while (1) {
        printf("client> ");
        fflush(stdout);

        if (!fgets(sendbuf, sizeof(sendbuf), stdin))
            break;

        if (strncmp(sendbuf, "quit", 4) == 0) {
            printf("Closing TLS session...\n");
            break;
        }

        SSL_write(ssl, sendbuf, strlen(sendbuf));

        int r = SSL_read(ssl, recvbuf, sizeof(recvbuf)-1);
        if (r > 0) {
            recvbuf[r] = '\0';
            printf("server> %s\n", recvbuf);
        } else {
            printf("Server closed connection.\n");
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    printf("Disconnected.\n");
    return 0;
}
