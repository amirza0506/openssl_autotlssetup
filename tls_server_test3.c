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

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        exit(EXIT_FAILURE);

    if (strcmp(alg, "RSA") == 0)
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

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
    if (!f) exit(EXIT_FAILURE);
    PEM_write_X509(f, cert);
    fclose(f);

    f = fopen(keyfile, "w");
    if (!f) exit(EXIT_FAILURE);
    PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    printf("Certificate saved to %s\n", certfile);
    printf("Private key saved to %s\n", keyfile);
}

int create_socket(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        exit(EXIT_FAILURE);

    listen(s, 5);
    return s;
}

/* ===================== NEW PART: CHAT HANDLER ===================== */
void *client_handler(void *arg)
{
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];

    if (fork() == 0)
    {
        // RECEIVE FROM CLIENT
        while (1)
        {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes <= 0)
                break;

            buffer[bytes] = '\0';
            printf("\n[Client]: %s\n", buffer);
        }

        printf("Client disconnected.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(0);
    }
    else
    {
        // SEND TO CLIENT
        char msg[BUFFER_SIZE];
        while (1)
        {
            printf("[Server]: ");
            fgets(msg, sizeof(msg), stdin);
            SSL_write(ssl, msg, strlen(msg));
        }
    }

    return NULL;
}
/* ================================================================ */

void run_server(const char *certfile,
                const char *keyfile,
                const char *group,
                int port)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)) {
        printf("Error loading cert/key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (group) {
        if (!SSL_CTX_set1_groups_list(ctx, group)) {
            printf("Warning: Group %s not supported\n", group);
        }
    }

    int sock = create_socket(port);

    printf("TLS server running on port %d\n", port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);

        int client = accept(sock, (struct sockaddr*)&addr, &len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) > 0) {
            printf("\nTLS Connection Established\n");
            printf("Protocol: %s\n", SSL_get_version(ssl));
            printf("Cipher: %s\n", SSL_get_cipher(ssl));

            pthread_t tid;
            pthread_create(&tid, NULL, client_handler, ssl);
            pthread_detach(tid);
        } else {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client);
        }
    }
}

int main(int argc, char **argv)
{
    const char *mode = NULL;
    const char *alg = NULL;
    const char *group = NULL;
    const char *certfile = NULL;
    const char *keyfile = NULL;
    int port = DEFAULT_PORT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0)
            mode = argv[++i];
        else if (strcmp(argv[i], "--alg") == 0)
            alg = argv[++i];
        else if (strcmp(argv[i], "--group") == 0)
            group = argv[++i];
        else if (strcmp(argv[i], "--cert") == 0)
            certfile = argv[++i];
        else if (strcmp(argv[i], "--key") == 0)
            keyfile = argv[++i];
        else if (strcmp(argv[i], "--port") == 0)
            port = atoi(argv[++i]);
    }

    if (!mode) {
        printf("Usage:\n");
        printf("--mode gen --alg RSA --cert server.crt --key server.key\n");
        printf("--mode server --cert server.crt --key server.key --group X25519 --port 4443\n");
        exit(1);
    }

    init_openssl();

    if (strcmp(mode, "gen") == 0) {

        if (!alg) {
            printf("Error: please choose algorithm using --alg\n");
            return EXIT_FAILURE;
        }

        if (!certfile || !keyfile) {
            printf("Error: please specify --cert and --key output files\n");
            return EXIT_FAILURE;
        }

        EVP_PKEY *pkey = generate_key(alg);
        X509 *cert = generate_cert(pkey);
        save_cert_key(cert, pkey, certfile, keyfile);

        EVP_PKEY_free(pkey);
        X509_free(cert);
    }
    else if (strcmp(mode, "server") == 0) {

        if (!certfile || !keyfile) {
            printf("Error: please specify --cert ,--key , --group and --port for server mode\n");
            return EXIT_FAILURE;
        }

        run_server(certfile, keyfile, group, port);
    }
    else {
        printf("Invalid mode\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
