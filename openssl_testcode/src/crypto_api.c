#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>

// =====================================================
// Utility helpers
// =====================================================
static void handle_err(const char *msg)
{
    fprintf(stderr, "[cryptoapi] %s\n", msg);
}

static int write_keypair(EVP_PKEY *pkey, const char *priv_path, const char *pub_path)
{
    FILE *fpriv = fopen(priv_path, "wb");
    FILE *fpub  = fopen(pub_path, "wb");
    if (!fpriv || !fpub) {
        handle_err("Cannot open key files for writing");
        if (fpriv) fclose(fpriv);
        if (fpub) fclose(fpub);
        return 0;
    }

    PEM_write_PrivateKey(fpriv, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(fpub, pkey);

    fclose(fpriv);
    fclose(fpub);
    return 1;
}

// =====================================================
// Classical cryptography (RSA example, OpenSSL 3.5 EVP API)
// =====================================================
void classical(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    printf("[classical] Generating RSA 2048 keypair...\n");

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) { handle_err("Failed to create RSA context"); goto done; }

    if (EVP_PKEY_keygen_init(ctx) <= 0) { handle_err("RSA keygen init failed"); goto done; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { handle_err("Set bits failed"); goto done; }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { handle_err("RSA key generation failed"); goto done; }

    if (!write_keypair(pkey, "rsa_private.pem", "rsa_public.pem"))
        handle_err("Failed to save RSA keypair");
    else
        printf("[classical] RSA keypair generated and saved.\n");

done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// =====================================================
// PQC placeholder (for liboqs or other PQC provider)
// =====================================================
void pqc(void)
{
    printf("[pqc] Placeholder for PQC algorithms (ML-DSA, Kyber, Dilithium...)\n");
    printf("[pqc] Implement with EVP_PKEY_CTX_new_from_name(NULL, \"<algoname>\", NULL)\n");
    printf("[pqc] Example: ctx = EVP_PKEY_CTX_new_from_name(NULL, \"ML-DSA-87\", NULL);\n");
}

// =====================================================
// KAZ placeholder (custom/local algorithm integration)
// =====================================================
void kaz(void)
{
    printf("[kaz] Placeholder for your proprietary or custom algorithm.\n");
    printf("[kaz] This can wrap external code or custom EVP providers.\n");
}

// =====================================================
// Hybrid mode (combine classical + PQC)
// =====================================================
void hybrid(void)
{
    printf("[hybrid] Running hybrid key exchange / signature...\n");
    printf("[hybrid] Typically combine RSA/ECDSA with PQC key material.\n");
    printf("[hybrid] You can merge classical() and pqc() contexts here.\n");
}

// =====================================================
// Simple demo for CLI
// =====================================================
#ifdef BUILD_DEMO
int main(void)
{
    classical();
    pqc();
    kaz();
    hybrid();
    return 0;
}
#endif
