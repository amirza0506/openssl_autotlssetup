#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

#define DEFAULT_PORT 4433
#define BUFFER_SIZE 1024

void init_openssl()
{
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "base");
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "oqs");

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

EVP_PKEY* generate_key(const char* alg)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx) {
        printf("Algorithm not available: %s\n", alg);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_keygen_init(ctx);

    if (strcmp(alg, "RSA") == 0)
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    if (strcmp(alg, "EC") == 0)
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        exit(EXIT_FAILURE);

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509* generate_cert(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, NULL))
        exit(EXIT_FAILURE);

    return x509;
}

void save_cert_key(X509 *cert, EVP_PKEY *pkey,
                   const char *certfile, const char *keyfile)
{
    FILE *f = fopen(certfile, "w");
    PEM_write_X509(f, cert);
    fclose(f);

    f = fopen(keyfile, "w");
    PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    printf("Saved cert: %s\n", certfile);
    printf("Saved key : %s\n", keyfile);
}

int create_socket(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    listen(s, 5);
    return s;
}

void *client_handler(void *arg)
{
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];

    while (1)
    {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';
        printf("[Client]: %s\n", buffer);

        SSL_write(ssl, buffer, bytes);
    }

    printf("Client disconnected\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return NULL;
}

void set_tls_version(SSL_CTX *ctx, const char *ver)
{
    if (!ver) return;

    if (!strcmp(ver, "SSL3"))
        SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
    else if (!strcmp(ver, "TLS1.0"))
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    else if (!strcmp(ver, "TLS1.1"))
        SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
    else if (!strcmp(ver, "TLS1.2"))
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    else if (!strcmp(ver, "TLS1.3"))
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
}

void run_server(const char *certfile,
                const char *keyfile,
                const char *group,
                const char *tlsver,
                const char *cipher,
                const char *ciphersuite,
                int port)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);

    set_tls_version(ctx, tlsver);

    if (cipher)
        SSL_CTX_set_cipher_list(ctx, cipher);

    if (ciphersuite)
        SSL_CTX_set_ciphersuites(ctx, ciphersuite);

    if (group)
        SSL_CTX_set1_groups_list(ctx, group);

    int sock = create_socket(port);

    printf("Server running on port %d\n", port);

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);

        int client = accept(sock, (struct sockaddr*)&addr, &len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) > 0)
        {
            printf("\nConnected\n");
            printf("Protocol: %s\n", SSL_get_version(ssl));
            printf("Cipher  : %s\n", SSL_get_cipher(ssl));

            pthread_t tid;
            pthread_create(&tid, NULL, client_handler, ssl);
            pthread_detach(tid);
        }
        else
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client);
        }
    }
}

int main(int argc, char **argv)
{
    const char *mode = NULL, *alg = NULL;
    const char *cert = NULL, *key = NULL;
    const char *group = NULL, *tlsver = NULL;
    const char *cipher = NULL, *ciphersuite = NULL;
    int port = DEFAULT_PORT;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--alg") && i + 1 < argc) alg = argv[++i];
        else if (!strcmp(argv[i], "--cert") && i + 1 < argc) cert = argv[++i];
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) key = argv[++i];
        else if (!strcmp(argv[i], "--group") && i + 1 < argc) group = argv[++i];
        else if (!strcmp(argv[i], "--tls") && i + 1 < argc) tlsver = argv[++i];
        else if (!strcmp(argv[i], "--cipher") && i + 1 < argc) cipher = argv[++i];
        else if (!strcmp(argv[i], "--ciphersuite") && i + 1 < argc) ciphersuite = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
    }

    if (mode == NULL)
    {
        printf("Error: --mode required\n");
        printf("Usage:\n");
        printf("./tls_server_test4 --mode gen --alg RSA --cert c.crt --key k.key\n");
        printf("./tls_server_test4 --mode server --cert c.crt --key k.key [--tls TLS1.3]\n");
        exit(EXIT_FAILURE);
    }

    init_openssl();

    if (strcmp(mode, "gen") == 0)
    {
        if (!alg || !cert || !key)
        {
            printf("Missing parameters for key generation\n");
            exit(EXIT_FAILURE);
        }

        EVP_PKEY *p = generate_key(alg);
        X509 *c = generate_cert(p);
        save_cert_key(c, p, cert, key);

        EVP_PKEY_free(p);
        X509_free(c);
    }
    else if (strcmp(mode, "server") == 0)
    {
        if (!cert || !key)
        {
            printf("Missing cert or key for server\n");
            exit(EXIT_FAILURE);
        }

        run_server(cert, key, group, tlsver, cipher, ciphersuite, port);
    }
    else
    {
        printf("Unknown mode\n");
    }

    return 0;
}
