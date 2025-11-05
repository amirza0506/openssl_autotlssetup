// pqc_tls_server_fixed.c
// Fixed: robust checks, CSR flow for ML-DSA, proper filenames, no segfaults.

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define DAYS_VALID 365
#define CERT_DIR "./certs"
#define PORT 4443

/* Helper */
void die(const char *msg) {
    fprintf(stderr, "❌ %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/* Try generate a key for provider name 'algo'; return NULL on failure. */
EVP_PKEY *generate_key(const char *algo) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!algo) return NULL;

    char nalgo[64];
    memset(nalgo, 0, sizeof(nalgo));
    strncpy(nalgo, algo, sizeof(nalgo)-1);
    for (char *p = nalgo; *p; ++p) *p = (char)toupper((unsigned char)*p);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, nalgo, NULL);
    if (!ctx) {
        fprintf(stderr, "⚠️ Algorithm '%s' not found, will attempt RSA as fallback.\n", algo);
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!ctx) {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set reasonable RSA keysize when generating RSA fallback */
    if (strcasecmp(nalgo, "RSA") == 0 || ctx == NULL) {
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Generate CSR for given key and common name */
X509_REQ *generate_csr(EVP_PKEY *pkey, const char *cn) {
    if (!pkey || !cn) return NULL;

    X509_REQ *req = X509_REQ_new();
    if (!req) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    X509_NAME *name = X509_NAME_new();
    if (!name) {
        X509_REQ_free(req);
        return NULL;
    }

    /* Minimal DN: CN only */
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)cn, -1, -1, 0)) {
        ERR_print_errors_fp(stderr);
        X509_NAME_free(name);
        X509_REQ_free(req);
        return NULL;
    }

    if (!X509_REQ_set_subject_name(req, name)) {
        ERR_print_errors_fp(stderr);
        X509_NAME_free(name);
        X509_REQ_free(req);
        return NULL;
    }

    if (!X509_REQ_set_pubkey(req, pkey)) {
        ERR_print_errors_fp(stderr);
        X509_NAME_free(name);
        X509_REQ_free(req);
        return NULL;
    }

    /* For PQC (ML-DSA) we must pass NULL digest; for RSA/ECDSA use SHA256 */
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") ||
          EVP_PKEY_is_a(pkey, "ML-DSA-65") ||
          EVP_PKEY_is_a(pkey, "ML-DSA-87"))) {
        md = EVP_sha256();
    }

    if (!X509_REQ_sign(req, pkey, md)) {
        ERR_print_errors_fp(stderr);
        X509_NAME_free(name);
        X509_REQ_free(req);
        return NULL;
    }

    X509_NAME_free(name);
    return req;
}

/* Sign CSR with CA key & cert and return newly minted X509 cert */
X509 *sign_csr_with_ca(X509_REQ *req, EVP_PKEY *ca_key, X509 *ca_crt) {
    if (!req || !ca_key || !ca_crt) return NULL;

    X509 *crt = X509_new();
    if (!crt) { ERR_print_errors_fp(stderr); return NULL; }

    if (!ASN1_INTEGER_set(X509_get_serialNumber(crt), 1)) {
        ERR_print_errors_fp(stderr);
        X509_free(crt);
        return NULL;
    }
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*DAYS_VALID);

    /* issuer from CA */
    X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
    /* subject from CSR */
    X509_set_subject_name(crt, X509_REQ_get_subject_name(req));

    EVP_PKEY *req_pub = X509_REQ_get_pubkey(req);
    if (!req_pub) { ERR_print_errors_fp(stderr); X509_free(crt); return NULL; }
    if (!X509_set_pubkey(crt, req_pub)) { ERR_print_errors_fp(stderr); EVP_PKEY_free(req_pub); X509_free(crt); return NULL; }
    EVP_PKEY_free(req_pub);

    /* Use NULL digest if CA key algorithm is PQC that disallows explicit digest */
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(ca_key, "ML-DSA-44") ||
          EVP_PKEY_is_a(ca_key, "ML-DSA-65") ||
          EVP_PKEY_is_a(ca_key, "ML-DSA-87"))) {
        md = EVP_sha256();
    }

    if (!X509_sign(crt, ca_key, md)) {
        ERR_print_errors_fp(stderr);
        X509_free(crt);
        return NULL;
    }

    return crt;
}

/* Create a cert directory if not present */
int ensure_cert_dir(void) {
    if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }
    return 0;
}

/* Generate a self-signed certificate (RSA will be self-signed fine).
 * For PQC algorithms we prefer CSR flow, so generate_server_cert_crs is used for ML-DSA. */
void generate_server_cert(const char *algo) {
    if (!algo) { fprintf(stderr, "algo missing\n"); return; }
    if (ensure_cert_dir() < 0) return;

    EVP_PKEY *pkey = generate_key(algo);
    if (!pkey) {
        fprintf(stderr, "❌ Failed to generate key for %s\n", algo);
        return;
    }

    X509 *crt = X509_new();
    if (!crt) { EVP_PKEY_free(pkey); die("X509_new failed"); }

    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 31536000L); /* 1 year */

    if (!X509_set_pubkey(crt, pkey)) { EVP_PKEY_free(pkey); X509_free(crt); die("set_pubkey failed"); }

    X509_NAME *name = X509_get_subject_name(crt);
    if (!name) { EVP_PKEY_free(pkey); X509_free(crt); die("get_subject_name failed"); }

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"MY", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"PTPKM_PQC_TLS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"TLS Server", -1, -1, 0);
    X509_set_issuer_name(crt, name);

    /* Use NULL digest for PQC signing algorithms if needed */
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") ||
          EVP_PKEY_is_a(pkey, "ML-DSA-65") ||
          EVP_PKEY_is_a(pkey, "ML-DSA-87"))) {
        md = EVP_sha256();
    }

    if (!X509_sign(crt, pkey, md)) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        X509_free(crt);
        fprintf(stderr, "❌ Failed to sign certificate.\n");
        return;
    }

    /* write files */
    char keypath[512], crtpath[512];
    snprintf(keypath, sizeof(keypath), "%s/server.key", CERT_DIR);
    snprintf(crtpath, sizeof(crtpath), "%s/server.crt", CERT_DIR);

    FILE *fk = fopen(keypath, "wb");
    if (!fk) { perror("fopen key"); EVP_PKEY_free(pkey); X509_free(crt); return; }
    if (!PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
    }
    fclose(fk);

    FILE *fc = fopen(crtpath, "wb");
    if (!fc) { perror("fopen cert"); EVP_PKEY_free(pkey); X509_free(crt); return; }
    if (!PEM_write_X509(fc, crt)) {
        ERR_print_errors_fp(stderr);
    }
    fclose(fc);

    printf("✅ Server certificate generated (algo: %s)\n", algo);

    EVP_PKEY_free(pkey);
    X509_free(crt);
}

/* Generate key + CSR then sign CSR using CA files (for ML-DSA). */
void generate_server_cert_crs(const char *algo, const char *name_base) {
    if (!algo || !name_base) return;
    if (ensure_cert_dir() < 0) return;

    /* generate key */
    EVP_PKEY *pkey = generate_key(algo);
    if (!pkey) { fprintf(stderr,"❌ keygen failed\n"); return; }

    /* CSR */
    X509_REQ *req = generate_csr(pkey, name_base);
    if (!req) { EVP_PKEY_free(pkey); fprintf(stderr,"❌ CSR generation failed\n"); return; }

    /* Save key and csr to predictable filenames */
    char keypath[512], csrpath[512], crtpath[512];
    snprintf(keypath, sizeof(keypath), "%s/%s.key", CERT_DIR, name_base);
    snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", CERT_DIR, name_base);
    snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", CERT_DIR, name_base);

    FILE *fk = fopen(keypath, "wb");
    if (!fk) { perror("fopen key"); X509_REQ_free(req); EVP_PKEY_free(pkey); return; }
    if (!PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
    }
    fclose(fk);

    FILE *fr = fopen(csrpath, "wb");
    if (!fr) { perror("fopen csr"); X509_REQ_free(req); EVP_PKEY_free(pkey); return; }
    if (!PEM_write_X509_REQ(fr, req)) {
        ERR_print_errors_fp(stderr);
    }
    fclose(fr);

    /* Load CA files: user must create these beforehand */
    char ca_crt_path[512], ca_key_path[512];
    snprintf(ca_crt_path, sizeof(ca_crt_path), "%s/ca.crt", CERT_DIR);
    snprintf(ca_key_path, sizeof(ca_key_path), "%s/ca.key", CERT_DIR);

    FILE *fca = fopen(ca_crt_path, "rb");
    FILE *fca_key = fopen(ca_key_path, "rb");
    if (!fca || !fca_key) {
        if (fca) fclose(fca);
        if (fca_key) fclose(fca_key);
        fprintf(stderr, "❌ CA files not found (%s and %s required)\n", ca_crt_path, ca_key_path);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    X509 *ca_crt = PEM_read_X509(fca, NULL, NULL, NULL);
    EVP_PKEY *ca_key = PEM_read_PrivateKey(fca_key, NULL, NULL, NULL);
    fclose(fca);
    fclose(fca_key);
    if (!ca_crt || !ca_key) {
        fprintf(stderr, "❌ Failed to read CA files\n");
        if (ca_crt) X509_free(ca_crt);
        if (ca_key) EVP_PKEY_free(ca_key);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    X509 *crt = sign_csr_with_ca(req, ca_key, ca_crt);
    if (!crt) {
        fprintf(stderr, "❌ Signing CSR failed\n");
        X509_free(ca_crt);
        EVP_PKEY_free(ca_key);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    FILE *fc = fopen(crtpath, "wb");
    if (!fc) { perror("fopen crt"); X509_free(crt); X509_free(ca_crt); EVP_PKEY_free(ca_key); X509_REQ_free(req); EVP_PKEY_free(pkey); return; }
    if (!PEM_write_X509(fc, crt)) ERR_print_errors_fp(stderr);
    fclose(fc);

    printf("✅ Generated key, CSR and CA-signed cert: %s, %s, %s\n", keypath, csrpath, crtpath);

    X509_free(crt);
    X509_free(ca_crt);
    EVP_PKEY_free(ca_key);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
}

/* Simple TLS server runner */
void run_server(void) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1, client = -1;
    struct sockaddr_in addr;

    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new failed");

    /* require server.crt and server.key exist */
    char server_crt[512], server_key[512];
    snprintf(server_crt, sizeof(server_crt), "%s/server.crt", CERT_DIR);
    snprintf(server_key, sizeof(server_key), "%s/server.key", CERT_DIR);
    if (access(server_crt, R_OK) != 0 || access(server_key, R_OK) != 0) {
        fprintf(stderr, "❌ server.crt or server.key missing in %s\n", CERT_DIR);
        SSL_CTX_free(ctx);
        return;
    }

    if (SSL_CTX_use_certificate_file(ctx, server_crt, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); SSL_CTX_free(ctx); return; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    int opt = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); close(sock); SSL_CTX_free(ctx); return; }
    if (listen(sock, 1) < 0) { perror("listen"); close(sock); SSL_CTX_free(ctx); return; }

    printf("🟢 Listening on %d...\n", PORT);
    client = accept(sock, NULL, NULL);
    if (client < 0) { perror("accept"); close(sock); SSL_CTX_free(ctx); return; }

    ssl = SSL_new(ctx);
    if (!ssl) { fprintf(stderr,"SSL_new failed\n"); close(client); close(sock); SSL_CTX_free(ctx); return; }
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("🔐 Handshake OK\n");
        const char *msg = "HTTP/1.1 200 OK\r\nContent-Length:12\r\n\r\nHello TLS\n";
        SSL_write(ssl, msg, (int)strlen(msg));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
}

/* main menu */
int main(void) {
    printf("1) Generate server certificate (self-signed or CSR+CA)\n2) Run server\nChoice: ");
    int c = 0;
    if (scanf("%d", &c) != 1) return 1;

    if (c == 1) {
        printf("Select Algorithm:\n1) RSA\n2) ML-DSA-44 (CSR + CA required)\n> ");
        int a = 0;
        if (scanf("%d", &a) != 1) return 1;
        if (a == 1) {
            generate_server_cert("RSA");
        } else if (a == 2) {
            /* provide a base name for files, e.g. 'server_mldsa44' */
            generate_server_cert_crs("ML-DSA-44", "server");
        } else {
            fprintf(stderr,"Invalid selection\n");
        }
    } else if (c == 2) {
        run_server();
    } else {
        fprintf(stderr,"Invalid choice\n");
    }

    return 0;
}
