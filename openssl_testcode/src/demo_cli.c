#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_api.h"

static void hexdump(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        printf("%02x", p[i]);
        if ((i+1) % 16 == 0) printf("\n"); else printf(" ");
    }
    if (n % 16) printf("\n");
}

int main(void) {
    if (crypto_init() != 0) {
        fprintf(stderr, "init failed\n"); return 1;
    }

    const unsigned char msg[] = "hello world";
    unsigned char *sig = NULL;
    size_t sig_len = 0;

    printf("[+] sign_hybrid\n");
    if (sign_hybrid(msg, sizeof(msg)-1, &sig, &sig_len) == 0) {
        printf("sig_len=%zu\n", sig_len);
        hexdump(sig, sig_len);
        free_buf(sig); /* crypto_api uses OPENSSL_free/ free correctly */
    } else {
        printf("hybrid sign failed\n");
    }

    crypto_cleanup();
    return 0;
}
