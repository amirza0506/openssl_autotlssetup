#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>      // For sockaddr_in, inet_pton
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERT_DIR "./certs"
#define PORT 4443
#define SERVER_IP "127.0.0.1"

// ===== Helper: Generate Key Based on Algorithm =====
EVP_PKEY *generate_key(const char *algo) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    EVP_PKEY *pkey = NULL;

    if (!ctx) {
        fprintf(stderr, "❌ Error: algorithm '%s' not found.\n", algo);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "❌ Keygen init failed for %s\n", algo);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (strcmp(algo, "RSA") == 0)
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        fprintf(stderr, "❌ Key generation failed for %s\n", algo);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// ===== Generate Client Certificate =====
void generate_client_cert(const char *algo) {
    EVP_PKEY *pkey = generate_key(algo);
    if (!pkey) return;

    X509 *crt = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 31536000L); // 1 year
    X509_set_pubkey(crt, pkey);

    X509_NAME *name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"TLS Client", -1, -1, 0);
    X509_set_issuer_name(crt, name);
    X509_sign(crt, pkey, EVP_sha256());

    system("mkdir -p ./certs");

    FILE *fk = fopen(CERT_DIR "/client.key", "wb");
    PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fk);

    FILE *fc = fopen(CERT_DIR "/client.crt", "wb");
    PEM_write_X509(fc, crt);
    fclose(fc);

    printf("✅ Client certificate generated (%s)\n", algo);
    EVP_PKEY_free(pkey);
    X509_free(crt);
}

// ===== Run TLS Client =====
void run_client() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    struct sockaddr_in addr;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());

    // Load certs
    if (!SSL_CTX_use_certificate_file(ctx, CERT_DIR "/client.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, CERT_DIR "/client.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // (Optional) verify CA
    if (SSL_CTX_load_verify_locations(ctx, CERT_DIR "/ca.crt", NULL) != 1)
        printf("⚠️ Warning: could not load CA cert for verification\n");

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("🔐 TLS handshake successful!\n");
        printf("🧩 Cipher: %s\n", SSL_get_cipher(ssl));

        const char *msg = "Hello from PQC TLS Client!";
        SSL_write(ssl, msg, strlen(msg));

        char buf[1024];
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("📩 Received: %s\n", buf);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}

// ===== Main Menu =====
int main() {
    printf("1) Generate client certificate\n2) Run TLS client\nChoice: ");
    int c; scanf("%d", &c);

    if (c == 1) {
        printf("Select Algorithm:\n1) RSA\n2) ML-DSA-44\n3) KAZ-DSA-3\n> ");
        int a; scanf("%d", &a);
        const char *algo = (a == 1) ? "RSA" : (a == 2) ? "ML-DSA-44" : "KAZ-DSA-3";
        generate_client_cert(algo);
    } else {
        run_client();
    }

    return 0;
}
