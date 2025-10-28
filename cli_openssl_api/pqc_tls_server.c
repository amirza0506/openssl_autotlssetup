#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <sys/socket.h>    
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERT_DIR "./certs"
#define PORT 4443

EVP_PKEY *generate_key(const char *algo) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(ctx);
    if (strcmp(algo, "RSA") == 0)
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_generate(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void generate_server_cert(const char *algo) {
    EVP_PKEY *pkey = generate_key(algo);
    X509 *crt = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 31536000L);
    X509_set_pubkey(crt, pkey);

    X509_NAME *name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"TLS Server", -1, -1, 0);
    X509_set_issuer_name(crt, name);
    X509_sign(crt, pkey, EVP_sha256());

    system("mkdir -p ./certs");
    FILE *fk = fopen(CERT_DIR "/server.key", "wb");
    PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fk);

    FILE *fc = fopen(CERT_DIR "/server.crt", "wb");
    PEM_write_X509(fc, crt);
    fclose(fc);

    printf("✅ Server certificate generated (%s)\n", algo);
    EVP_PKEY_free(pkey);
    X509_free(crt);
}

void run_server() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock, client;
    struct sockaddr_in addr;   

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_use_certificate_file(ctx, CERT_DIR "/server.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, CERT_DIR "/server.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("🟢 Server listening on port %d...\n", PORT);

    client = accept(sock, NULL, NULL);
    if (client < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0)
        ERR_print_errors_fp(stderr);
    else
        printf("🔐 TLS handshake successful!\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
}

int main() {
    printf("1) Generate server certificate\n2) Run server\nChoice: ");
    int c; scanf("%d", &c);

    if (c == 1) {
        printf("Select Algorithm:\n1) RSA\n2) ML-DSA-44\n> ");
        int a; scanf("%d", &a);
        generate_server_cert(a == 1 ? "RSA" : "ML-DSA-44");
    } else {
        run_server();
    }

    return 0;
}
