#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>

#define CA_DIR "./certs"

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

EVP_PKEY *generate_key(const char *algo) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_from_name");
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("EVP_PKEY_keygen_init");
    if (strcmp(algo, "RSA") == 0)
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) die("EVP_PKEY_generate");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void generate_ca(const char *algo) {
    EVP_PKEY *pkey = generate_key(algo);
    X509 *x509 = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"PQC Root CA", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    system("mkdir -p ./certs");
    FILE *fkey = fopen(CA_DIR "/ca.key", "wb");
    PEM_write_PrivateKey(fkey, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fkey);

    FILE *fcrt = fopen(CA_DIR "/ca.crt", "wb");
    PEM_write_X509(fcrt, x509);
    fclose(fcrt);

    printf("✅ CA generated using %s\n", algo);
    EVP_PKEY_free(pkey);
    X509_free(x509);
}

int main() {
    printf("Select CA Algorithm:\n1) RSA\n2) ML-DSA-44\nChoice: ");
    int choice; scanf("%d", &choice);
    if (choice == 1) generate_ca("RSA");
    else generate_ca("ML-DSA-44");
    return 0;
}
