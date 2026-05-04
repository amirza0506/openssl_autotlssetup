#ifndef CRYPTO_H
#define CRYPTO_H

int encrypt(unsigned char *plaintext, int len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);

#endif
