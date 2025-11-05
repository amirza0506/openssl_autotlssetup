// pqc_tls_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERT_DIR "./certs"
#define PORT 4443
#define DAYS_VALID 365

static void die(const char *msg) {
    fprintf(stderr, "❌ %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int ensure_cert_dir(void) {
    if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }
    return 0;
}

static EVP_PKEY *generate_key(const char *algo) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    if (!ctx) {
        fprintf(stderr, "⚠️ Algorithm %s unavailable, fallback to RSA.\n", algo);
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("EVP_PKEY_keygen_init");
    if (strcasecmp(algo, "RSA") == 0) EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) die("EVP_PKEY_generate");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Generate client CSR */
static X509_REQ *generate_csr(EVP_PKEY *pkey, const char *cn) {
    X509_REQ *req = X509_REQ_new();
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);

    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") || EVP_PKEY_is_a(pkey, "ML-DSA-65") || EVP_PKEY_is_a(pkey, "ML-DSA-87")))
        md = EVP_sha256();

    if (!X509_REQ_sign(req, pkey, md)) die("Failed to sign CSR");
    X509_NAME_free(name);
    return req;
}

/* Sign client CSR with CA */
static X509 *sign_csr_with_ca(X509_REQ *req, EVP_PKEY *ca_key, X509 *ca_crt) {
    X509 *crt = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*DAYS_VALID);
    X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(crt, X509_REQ_get_subject_name(req));
    X509_set_pubkey(crt, X509_REQ_get_pubkey(req));

    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(ca_key, "ML-DSA-44") || EVP_PKEY_is_a(ca_key, "ML-DSA-65") || EVP_PKEY_is_a(ca_key, "ML-DSA-87")))
        md = EVP_sha256();
    if (!X509_sign(crt, ca_key, md)) die("CA sign failed");
    return crt;
}

static void generate_client_cert(const char *algo) {
    if (ensure_cert_dir() < 0) return;

    EVP_PKEY *pkey = generate_key(algo);
    X509_REQ *req = generate_csr(pkey, "TLS_Client");

    /* Save CSR */
    FILE *fk = fopen(CERT_DIR "/client.key", "wb");
    FILE *fr = fopen(CERT_DIR "/client.csr", "wb");
    PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_X509_REQ(fr, req);
    fclose(fk);
    fclose(fr);
    printf("✅ Generated client key & CSR\n");

    /* Load CA */
    FILE *fca = fopen(CERT_DIR "/ca.crt", "rb");
    FILE *fca_key = fopen(CERT_DIR "/ca.key", "rb");
    if (!fca || !fca_key) die("CA missing");
    X509 *ca_crt = PEM_read_X509(fca, NULL, NULL, NULL);
    EVP_PKEY *ca_key = PEM_read_PrivateKey(fca_key, NULL, NULL, NULL);
    fclose(fca);
    fclose(fca_key);

    X509 *crt = sign_csr_with_ca(req, ca_key, ca_crt);
    FILE *fc = fopen(CERT_DIR "/client.crt", "wb");
    PEM_write_X509(fc, crt);
    fclose(fc);
    printf("✅ Client cert signed by CA\n");

    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    X509_free(crt);
    X509_free(ca_crt);
    EVP_PKEY_free(ca_key);
}

/* Connect to PQC TLS server */
static void run_client(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new");

    SSL *ssl;
    int sock;
    struct sockaddr_in addr;

    /* Optional: load client cert for mTLS */
    SSL_CTX_use_certificate_file(ctx, CERT_DIR "/client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, CERT_DIR "/client.key", SSL_FILETYPE_PEM);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        SSL_CTX_free(ctx);
        return;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("🔐 Connected to PQC TLS Server!\n");
        char buf[1024];
        int n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = 0;
            printf("📨 Received: %s\n", buf);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}

int main(void) {
    printf("1) Generate client cert via CA\n2) Connect to server\n> ");
    int c;
    scanf("%d", &c);
    if (c == 1) generate_client_cert("ML-DSA-44");
    else if (c == 2) run_client();
    else printf("Invalid\n");
    return 0;
}
