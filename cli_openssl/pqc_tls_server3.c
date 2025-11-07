// pqc_tls_server.c
// Server: generate key+CSR, sign with CA (if present), or self-sign; run TLS server and print handshake + cert info.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define CERT_DIR "./certs"
#define PORT 4443
#define DAYS_VALID 365

static void die(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void ensure_cert_dir(void) {
    if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        exit(1);
    }
}

static EVP_PKEY *generate_key_by_name(const char *name) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!pctx) {
        fprintf(stderr, "⚠ provider/type '%s' NB not available, falling back to RSA\n", name);
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pctx) die("EVP_PKEY_CTX_new_from_name RSA fallback failed");
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) die("EVP_PKEY_keygen_init");
    if (strcasecmp(name, "RSA") == 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) die("set rsa bits failed");
    }
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) die("EVP_PKEY_generate");
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* Create CSR (X509_REQ) signed by the private key */
static X509_REQ *create_csr(EVP_PKEY *pkey, const char *cn) {
    X509_REQ *req = X509_REQ_new();
    if (!req) die("X509_REQ_new");

    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);

    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") || EVP_PKEY_is_a(pkey, "ML-DSA-65") || EVP_PKEY_is_a(pkey, "ML-DSA-87")))
        md = EVP_sha256();

    if (!X509_REQ_sign(req, pkey, md)) die("X509_REQ_sign failed");
    X509_NAME_free(name);
    return req;
}

/* Load CA key & cert if present */
static int load_ca(EVP_PKEY **out_key, X509 **out_crt) {
    char kp[256], cp[256];
    snprintf(kp, sizeof(kp), "%s/ca.key", CERT_DIR);
    snprintf(cp, sizeof(cp), "%s/ca.crt", CERT_DIR);
    FILE *fk = fopen(kp, "rb");
    FILE *fc = fopen(cp, "rb");
    if (!fk || !fc) {
        if (fk) fclose(fk);
        if (fc) fclose(fc);
        return 0;
    }
    *out_key = PEM_read_PrivateKey(fk, NULL, NULL, NULL);
    *out_crt = PEM_read_X509(fc, NULL, NULL, NULL);
    fclose(fk); fclose(fc);
    if (!*out_key || !*out_crt) return 0;
    return 1;
}

/* Sign CSR with CA key+cert; choose digest smartly (NULL for ML-DSA). */
static X509 *sign_csr_with_ca(X509_REQ *req, EVP_PKEY *ca_key, X509 *ca_crt) {
    X509 *crt = X509_new();
    if (!crt) die("X509_new failed");
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*DAYS_VALID);

    X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(crt, X509_REQ_get_subject_name(req));

    EVP_PKEY *req_pub = X509_REQ_get_pubkey(req);
    X509_set_pubkey(crt, req_pub);
    EVP_PKEY_free(req_pub);

    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(ca_key, "ML-DSA-44") || EVP_PKEY_is_a(ca_key, "ML-DSA-65") || EVP_PKEY_is_a(ca_key, "ML-DSA-87")))
        md = EVP_sha256();

    if (!X509_sign(crt, ca_key, md)) {
        // X509_free(crt);
        die("X509_sign (CA) failed");
    }
    return crt;
}

static void write_pem_files(EVP_PKEY *pkey, X509_REQ *req, X509 *crt, const char *basename) {
    ensure_cert_dir();
    char keypath[256], csrpath[256], crtpath[256];
    snprintf(keypath, sizeof(keypath), "%s/%s.key", CERT_DIR, basename);
    snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", CERT_DIR, basename);
    snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", CERT_DIR, basename);

    FILE *fk = fopen(keypath, "wb"); if (!fk) die("open keypath");
    if (!PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) die("write key");
    fclose(fk);

    FILE *fr = fopen(csrpath, "wb"); if (!fr) die("open csrpath");
    if (!PEM_write_X509_REQ(fr, req)) die("write csr");
    fclose(fr);

    if (!crt) {
        /* no CA sign: self-sign */
        X509 *self = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(self), 1);
        X509_gmtime_adj(X509_get_notBefore(self), 0);
        X509_gmtime_adj(X509_get_notAfter(self), (long)60*60*24*DAYS_VALID);
        X509_set_subject_name(self, X509_REQ_get_subject_name(req));
        X509_set_issuer_name(self, X509_REQ_get_subject_name(req));
        X509_set_pubkey(self, X509_REQ_get_pubkey(req));
        const EVP_MD *md = NULL;
        if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") || EVP_PKEY_is_a(pkey, "ML-DSA-65") || EVP_PKEY_is_a(pkey, "ML-DSA-87")))
            md = EVP_sha256();
        if (!X509_sign(self, pkey, md)) die("self sign failed");
        FILE *fc = fopen(crtpath, "wb"); if (!fc) die("open crtpath");
        if (!PEM_write_X509(fc, self)) die("write crt");
        fclose(fc);
        X509_free(self);
    } else {
        FILE *fc = fopen(crtpath, "wb"); if (!fc) die("open crtpath ca signed");
        if (!PEM_write_X509(fc, crt)) die("write crt ca signed");
        fclose(fc);
    }
    printf("Wrote %s, %s, %s\n", keypath, csrpath, crtpath);
}

static void print_x509_info(X509 *cert) {
    if (!cert) { printf("(no cert)\n"); return; }
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *iss  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("Subject: %s\nIssuer : %s\n", subj, iss);
    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (pk) {
        printf("Pubkey bits: %d\n", EVP_PKEY_bits(pk));
        printf("Pubkey algo: %s\n", OBJ_nid2ln(EVP_PKEY_base_id(pk)));
        EVP_PKEY_free(pk);
    }
    const X509_ALGOR *sigalg = NULL; const ASN1_BIT_STRING *sig = NULL;
    X509_get0_signature(&sig, &sigalg, cert);
    char algname[128]; OBJ_obj2txt(algname, sizeof(algname), sigalg->algorithm, 1);
    printf("Signature alg: %s\n", algname);
    OPENSSL_free(subj); OPENSSL_free(iss);
}

/* Run TLS server and print handshake + cert info */
static void run_server(void) {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); if (!ctx) die("SSL_CTX_new");

    /* Prefer PQC group if available */
    SSL_CTX_set1_groups_list(ctx, "MLKEM512:X25519");

    /* Load server cert/key */
    char srv_crt[256], srv_key[256];
    snprintf(srv_crt, sizeof(srv_crt), "%s/server.crt", CERT_DIR);
    snprintf(srv_key, sizeof(srv_key), "%s/server.key", CERT_DIR);
    if (access(srv_crt, R_OK) != 0 || access(srv_key, R_OK) != 0) die("server cert/key missing - generate first");

    if (SSL_CTX_use_certificate_file(ctx, srv_crt, SSL_FILETYPE_PEM) <= 0) die("SSL_CTX_use_certificate_file");
    if (SSL_CTX_use_PrivateKey_file(ctx, srv_key, SSL_FILETYPE_PEM) <= 0) die("SSL_CTX_use_PrivateKey_file");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0}; addr.sin_family = AF_INET; addr.sin_port = htons(PORT); addr.sin_addr.s_addr = INADDR_ANY;
    int on=1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    bind(sock, (struct sockaddr*)&addr, sizeof(addr)); listen(sock, 1);
    printf("Server listening on %d\n", PORT);

    int client = accept(sock, NULL, NULL);
    SSL *ssl = SSL_new(ctx); SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) { ERR_print_errors_fp(stderr); die("SSL_accept failed"); }
    printf("Handshake OK\n");

    /* Cipher */
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const char *cname = cipher ? SSL_CIPHER_get_name(cipher) : "Unknown";
    printf("Cipher suite: %s\n", cname);

    /* Group */
    int gid = SSL_get_shared_group(ssl, 0);
    const char *gname = "unknown";
    if (gid > 0) {
        const char *tmp = SSL_group_to_name(ssl, gid);
        if (tmp) gname = tmp;
    }
    printf("KEX group: %s (id=%d)\n", gname, gid);

    X509 *peer = SSL_get_certificate(ssl); /* server's own cert loaded in ctx; print it */
    if (peer) {
        printf("Server certificate:\n");
        print_x509_info(peer);
    }

    /* send simple response */
    const char *msg = "HTTP/1.1 200 OK\r\nContent-Length:12\r\n\r\nHello TLS\n";
    SSL_write(ssl, msg, (int)strlen(msg));

    SSL_shutdown(ssl); SSL_free(ssl); close(client); close(sock); SSL_CTX_free(ctx);
}

int main(void) {
    OPENSSL_init_crypto(0, NULL);
    printf("PQC TLS Server (with CA signing)\n");
    printf("1) Generate server key+CSR and sign with local CA (if present)\n2) Run server\nChoice: ");
    int c=0; if (scanf("%d", &c) != 1) return 1;

    if (c == 1) {
        printf("Select algorithm: 1) RSA 2) ML-DSA-44\nChoice: ");
        int a=0; if (scanf("%d", &a) != 1) return 1;
        const char *algo = (a==2) ? "ML-DSA-44" : "RSA";
        ensure_cert_dir();
        EVP_PKEY *pkey = generate_key_by_name(algo);
        X509_REQ *req = create_csr(pkey, "server");

        /* try load CA */
        EVP_PKEY *ca_key = NULL; X509 *ca_crt = NULL;
        int have_ca = load_ca(&ca_key, &ca_crt);
        X509 *signed_cert = NULL;
        if (have_ca) {
            signed_cert = sign_csr_with_ca(req, ca_key, ca_crt);
            /* write using base name "server" */
            write_pem_files(pkey, req, signed_cert, "server");
            EVP_PKEY_free(ca_key); X509_free(ca_crt); X509_free(signed_cert);
        } else {
            printf("No CA found in %s - will self-sign certificate.\n", CERT_DIR);
            write_pem_files(pkey, req, NULL, "server");
        }
        X509_REQ_free(req); EVP_PKEY_free(pkey);
    } else if (c == 2) {
        run_server();
    } else {
        printf("Invalid choice\n");
    }
    return 0;
}
