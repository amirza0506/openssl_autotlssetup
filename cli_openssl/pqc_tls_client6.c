#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define CERT_DIR "./certs"
#define PORT 4443
#define DAYS_VALID 365
static X509 *g_ca_cert = NULL;

static void die(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void ensure_cert_dir(void) {
    if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        exit(1);
    }
}

static void try_load_providers(void) {
    const char *prov_names[] = {
        "oqsprovider", "oqs", "pqcprovider", "pqc", "apple", "microsoft", "ibmpqc", NULL
    };
    for (const char **p = prov_names; *p; ++p) {
        OSSL_PROVIDER *pr = OSSL_PROVIDER_load(NULL, *p);
        if (pr) {
            printf("Loaded provider: %s\n", *p);
        } else {
            ERR_clear_error();
        }
    }
}

static EVP_PKEY *generate_key_by_name(const char *name) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!pctx) {
        fprintf(stderr, "⚠ provider/type '%s' not available; falling back to RSA\n", name);
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pctx) die("EVP_PKEY_CTX_new_from_name fallback failed");
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) die("EVP_PKEY_keygen_init");
    if (strcasecmp(name, "RSA") == 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) die("set rsa bits failed");
    }
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) die("EVP_PKEY_generate");
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static void sign_x509_req_with_key(X509_REQ *req, EVP_PKEY *pkey) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die("EVP_MD_CTX_new");
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        die("EVP_DigestSignInit failed for CSR");
    }
    if (X509_REQ_sign_ctx(req, mdctx) <= 0) {
        EVP_MD_CTX_free(mdctx);
        die("X509_REQ_sign_ctx failed");
    }
    EVP_MD_CTX_free(mdctx);
}

static void sign_x509_with_key(X509 *crt, EVP_PKEY *pkey) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die("EVP_MD_CTX_new");
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        die("EVP_DigestSignInit failed for cert");
    }
    if (X509_sign_ctx(crt, mdctx) <= 0) {
        EVP_MD_CTX_free(mdctx);
        die("X509_sign_ctx failed");
    }
    EVP_MD_CTX_free(mdctx);
}

static X509_REQ *create_csr(EVP_PKEY *pkey, const char *cn) {
    X509_REQ *req = X509_REQ_new();
    if (!req) die("X509_REQ_new");
    X509_NAME *name = X509_NAME_new();
    if (!name) die("X509_NAME_new");
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
            (unsigned char *)cn, -1, -1, 0))
        die("X509_NAME_add_entry_by_txt");
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);
    sign_x509_req_with_key(req, pkey);
    X509_NAME_free(name);
    return req;
}

static int load_ca(EVP_PKEY **out_key, X509 **out_crt, const char *ca_basename) {
    char kp[512], cp[512];
    snprintf(kp, sizeof(kp), "%s/%s.key", CERT_DIR, ca_basename);
    snprintf(cp, sizeof(cp), "%s/%s.crt", CERT_DIR, ca_basename);
    FILE *fk = fopen(kp, "rb");
    FILE *fc = fopen(cp, "rb");
    if (!fk || !fc) {
        if (fk) fclose(fk);
        if (fc) fclose(fc);
        return 0;
    }
    *out_key = PEM_read_PrivateKey(fk, NULL, NULL, NULL);
    *out_crt = PEM_read_X509(fc, NULL, NULL, NULL);
    fclose(fk); 
    fclose(fc);
    if (!*out_key || !*out_crt) return 0;
    if (!X509_check_private_key(*out_crt, *out_key)) {
        fprintf(stderr, "ERROR: CA key does not match CA certificate\n");
        EVP_PKEY_free(*out_key);
        X509_free(*out_crt);
        *out_key = NULL; 
        *out_crt = NULL;
        return 0;
    }
    return 1;
}

static void write_pems(EVP_PKEY *pkey, X509_REQ *req, X509 *crt, const char *basename) {
    ensure_cert_dir();
    char keypath[512], csrpath[512], crtpath[512];
    snprintf(keypath, sizeof(keypath), "%s/%s.key", CERT_DIR, basename);
    snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", CERT_DIR, basename);
    snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", CERT_DIR, basename);

    FILE *fk = fopen(keypath, "wb"); 
    if (!fk) die("open keypath");
    if (!PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) die("write key");
    fclose(fk);

    FILE *fr = fopen(csrpath, "wb"); 
    if (!fr) die("open csrpath");
    if (!PEM_write_X509_REQ(fr, req)) die("write csr");
    fclose(fr);

    if (!crt) {
        X509 *self = X509_new();
        if (!self) die("X509_new self");
        ASN1_INTEGER_set(X509_get_serialNumber(self), 1);
        X509_gmtime_adj(X509_get_notBefore(self), 0);
        X509_gmtime_adj(X509_get_notAfter(self), 
                        (long)60*60*24*DAYS_VALID);
        if (!X509_set_subject_name(self, X509_REQ_get_subject_name(req)))
            die("set subject");
        if (!X509_set_issuer_name(self, 
            X509_REQ_get_subject_name(req)))
            die("set issuer");
        EVP_PKEY *req_pub = X509_REQ_get_pubkey(req);
        if (!req_pub) die("X509_REQ_get_pubkey");
        X509_set_pubkey(self, req_pub);
        EVP_PKEY_free(req_pub);
        sign_x509_with_key(self, pkey);
        FILE *fc = fopen(crtpath, "wb"); 
        if (!fc) die("open crtpath");
        if (!PEM_write_X509(fc, self)) die("write crt");
        fclose(fc);
        X509_free(self);
    } else {
        FILE *fc = fopen(crtpath, "wb"); 
        if (!fc) die("open crtpath ca signed");
        if (!PEM_write_X509(fc, crt)) die("write crt ca signed");
        fclose(fc);
    }
    printf("Wrote %s, %s, %s\n", keypath, csrpath, crtpath);
}

static void do_connect_external(const char *ip, const char *port) {

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "openssl s_client -connect %s:%s",
             ip, port);

    printf("\n=== Running OpenSSL CLI Command ===\n%s\n\n", cmd);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen failed");
        return;
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), fp)) {
        fputs(buffer, stdout);
    }

    pclose(fp);
}

int main(int argc, char **argv) {
    int insecure = 0;
    const char *groups = NULL;
    const char *host = "127.0.0.1";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--insecure") == 0) insecure = 1;
        else if (strcmp(argv[i], "--groups") == 0 && i+1 < argc) groups = argv[++i];
        else if (strcmp(argv[i], "--host") == 0 && i+1 < argc) host = argv[++i];
    }

    printf("PQC TLS Client\n");
    printf("1) Generate client key+CSR and sign via local CA (if present)\n");
    printf("2) Connect to server via openssl s_client\n");
    printf("Choice: ");

    int c = 0; 
    if (scanf("%d", &c) != 1) return 0;

    if (c == 1) {

        printf("Select algorithm: 1) RSA 2) ML-DSA-44\nChoice: ");
        int a = 0; 
        if (scanf("%d", &a) != 1) return 0;
        const char *algo = (a == 2) ? "ML-DSA-44" : "RSA";

        ensure_cert_dir();
        if (!OPENSSL_init_crypto(0, NULL)) die("OPENSSL_init_crypto");
        try_load_providers();

        EVP_PKEY *pkey = generate_key_by_name(algo);
        X509_REQ *req = create_csr(pkey, "client");

        EVP_PKEY *ca_key = NULL; 
        X509 *ca_crt = NULL;
        int have_ca = load_ca(&ca_key, &ca_crt, "ca");

        X509 *signed_cert = NULL;
        if (have_ca) {
            signed_cert = X509_new();
            ASN1_INTEGER_set(X509_get_serialNumber(signed_cert), 2);
            X509_gmtime_adj(X509_get_notBefore(signed_cert), 0);
            X509_gmtime_adj(X509_get_notAfter(signed_cert), 
                            (long)60*60*24*DAYS_VALID);
            X509_set_issuer_name(signed_cert, X509_get_subject_name(ca_crt));
            X509_set_subject_name(signed_cert, 
                                  X509_REQ_get_subject_name(req));
            EVP_PKEY *req_pub = X509_REQ_get_pubkey(req);
            X509_set_pubkey(signed_cert, req_pub);
            EVP_PKEY_free(req_pub);
            sign_x509_with_key(signed_cert, ca_key);
            write_pems(pkey, req, signed_cert, "client");
            EVP_PKEY_free(ca_key); 
            X509_free(ca_crt); 
            X509_free(signed_cert);
        } else {
            printf("No CA found in %s - will self-sign certificate.\n", CERT_DIR);
            write_pems(pkey, req, NULL, "client");
        }

        X509_REQ_free(req);
        EVP_PKEY_free(pkey);

    } else if (c == 2) {

        char ip[128], port[16];

        printf("Enter server IP: ");
        scanf("%127s", ip);

        printf("Enter server port: ");
        scanf("%15s", port);

        printf("\nConnecting via OpenSSL CLI...\n");
        do_connect_external(ip, port);

    } else {
        printf("Invalid choice\n");
    }

    return 0;
}
