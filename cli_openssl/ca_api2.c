// pqc_tls_ca.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define CERT_DIR "./certs"
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
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    if (!ctx) {
        fprintf(stderr, "⚠️ Algorithm %s unavailable, using RSA fallback.\n", algo);
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!ctx) die("EVP_PKEY_CTX_new_from_name");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("EVP_PKEY_keygen_init");
    if (strcasecmp(algo, "RSA") == 0) EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) die("EVP_PKEY_generate");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void generate_ca(const char *algo) {
    if (ensure_cert_dir() < 0) return;

    EVP_PKEY *pkey = generate_key(algo);
    X509 *crt = X509_new();
    if (!crt) die("X509_new");

    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*DAYS_VALID);

    X509_set_pubkey(crt, pkey);
    X509_NAME *name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"MY", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"PQC_CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"PQC Root CA", -1, -1, 0);
    X509_set_issuer_name(crt, name);

    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") || EVP_PKEY_is_a(pkey, "ML-DSA-65") || EVP_PKEY_is_a(pkey, "ML-DSA-87")))
        md = EVP_sha256();

    if (!X509_sign(crt, pkey, md)) die("X509_sign");

    char keypath[512], crtpath[512];
    snprintf(keypath, sizeof(keypath), "%s/ca.key", CERT_DIR, algo);
    snprintf(crtpath, sizeof(crtpath), "%s/ca.crt", CERT_DIR, algo);

    FILE *fk = fopen(keypath, "wb");
    FILE *fc = fopen(crtpath, "wb");
    if (!fk || !fc) die("fopen");
    PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_X509(fc, crt);
    fclose(fk);
    fclose(fc);

    printf("✅ Generated CA cert & key: %s, %s\n", crtpath, keypath);
    EVP_PKEY_free(pkey);
    X509_free(crt);
}

int main(void) {
    printf("Select CA algorithm:\n1) RSA\n2) ML-DSA-44\n> ");
    int c = 0;
    if (scanf("%d", &c) != 1) return 1;
    if (c == 1) generate_ca("RSA");
    else if (c == 2) generate_ca("ML-DSA-44");
    else fprintf(stderr, "Invalid option\n");
    return 0;
}
