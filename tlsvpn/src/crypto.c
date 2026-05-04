#include <openssl/evp.h>
#include <string.h>

int encrypt(unsigned char *plaintext, int len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, tmplen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);

    EVP_CIPHER_CTX_free(ctx);
    return outlen + tmplen;
}

int decrypt(unsigned char *ciphertext, int len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, tmplen;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, len);
    EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen);

    EVP_CIPHER_CTX_free(ctx);
    return outlen + tmplen;
}
