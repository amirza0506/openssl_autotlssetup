#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

int tcp_connect(const char *ip, int port)
{
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        exit(1);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server.sin_addr) <= 0)
    {
        printf("Invalid IP address\n");
        exit(1);
    }

    printf("Connecting to %s:%d...\n", ip, port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("Connection failed");
        exit(1);
    }

    printf("TCP connection established\n");

    return sock;
}

void print_certificate_info(SSL *ssl)
{
    X509 *cert = SSL_get1_peer_certificate(ssl);

    if (!cert)
    {
        printf("No certificate received.\n");
        return;
    }

    X509_print_fp(stdout, cert);//untuk keluarkan public key dan signature algo
    PEM_write_X509(stdout,cert);//untuk keluarkan pem atau cert in pem format

    char *line;

    printf("Subject: ");
    X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
    printf("\n");


    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    OPENSSL_free(line);

    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    OPENSSL_free(line);

    EVP_PKEY *pkey = X509_get_pubkey(cert);

    if (pkey)
    {
        printf("Key Size: %d bits\n", EVP_PKEY_bits(pkey));
        EVP_PKEY_free(pkey);
    }

    X509_free(cert);
}

int main()
{
    char ip[256];
    int port;

    printf("Enter server IP: ");
    scanf("%255s", ip);

    printf("Enter server port: ");
    scanf("%d", &port);

    init_openssl();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx)
    {
        printf("Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    int sock = tcp_connect(ip, port);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    printf("Starting TLS handshake...\n");

    if (SSL_connect(ssl) <= 0)
    {
        printf("TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("TLS handshake successful\n\n");

        printf("TLS Version: %s\n", SSL_get_version(ssl));
        printf("Cipher: %s\n", SSL_get_cipher(ssl));

        printf("\nCertificate Information:\n");
        print_certificate_info(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    close(sock);
    SSL_CTX_free(ctx);

    cleanup_openssl();

    return 0;
}
