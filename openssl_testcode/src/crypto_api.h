#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* initialize/cleanup */
int crypto_init(void);
void crypto_cleanup(void);

/* classic RSA/ECDSA style functions */
int generate_key_classical(unsigned char **out_der, size_t *out_len); /* returns DER-encoded private key */
int sign_classical(const unsigned char *data, size_t data_len,
                   unsigned char **sig, size_t *sig_len);
int verify_classical(const unsigned char *data, size_t data_len,
                     const unsigned char *sig, size_t sig_len);

/* PQC (liboqs) functions - may be stubbed if liboqs absent */
int generate_key_pqc(unsigned char **pub, size_t *pub_len, unsigned char **priv, size_t *priv_len);
int sign_pqc(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len);
int verify_pqc(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len);

/* "kaz" algorithm placeholder (user-extensible) */
int generate_key_kaz(unsigned char **pub, size_t *pub_len, unsigned char **priv, size_t *priv_len);
int sign_kaz(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len);
int verify_kaz(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len);

/* hybrid: returns a concatenated signature (classical||pqc) or similar */
int sign_hybrid(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len);
int verify_hybrid(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len);

/* helpers */
void free_buf(unsigned char *p);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_API_H */
