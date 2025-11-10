#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
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
    exit(1);
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
        fprintf(stderr, "⚠ provider/type '%s' not available; fallback RSA\n", name);
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pctx) die("EVP_PKEY_CTX_new_from_name");
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) die("EVP_PKEY_keygen_init");
    if (strcasecmp(name, "RSA") == 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) die("set rsa bits failed");
    }
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) die("EVP_PKEY_generate");
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static X509_REQ *create_csr(EVP_PKEY *pkey, const char *cn) {
    X509_REQ *req = X509_REQ_new(); if (!req) die("X509_REQ_new");
    X509_NAME *name = X509_NAME_new(); if (!name) die("X509_NAME_new");
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey,"ML-DSA-44")||EVP_PKEY_is_a(pkey,"ML-DSA-65")||EVP_PKEY_is_a(pkey,"ML-DSA-87")))
        md = EVP_sha256();
    if (!X509_REQ_sign(req, pkey, md)) die("X509_REQ_sign");
    X509_NAME_free(name);
    return req;
}

static int load_ca(EVP_PKEY **out_key, X509 **out_crt, const char *ca_basename) {
    char kp[512], cp[512];
    snprintf(kp, sizeof(kp), "%s/%s.key", CERT_DIR, ca_basename);
    snprintf(cp, sizeof(cp), "%s/%s.crt", CERT_DIR, ca_basename);
    FILE *fk = fopen(kp, "rb");
    FILE *fc = fopen(cp, "rb");
    if (!fk || !fc) { if (fk) fclose(fk); if (fc) fclose(fc); return 0; }
    *out_key = PEM_read_PrivateKey(fk, NULL, NULL, NULL);
    *out_crt = PEM_read_X509(fc, NULL, NULL, NULL);
    fclose(fk); fclose(fc);
    if (!*out_key || !*out_crt) return 0;
    return 1;
}

static X509 *sign_csr_with_ca(X509_REQ *req, EVP_PKEY *ca_key, X509 *ca_crt) {
    X509 *crt = X509_new(); if (!crt) die("X509_new");
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*DAYS_VALID);
    X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(crt, X509_REQ_get_subject_name(req));
    X509_set_pubkey(crt, X509_REQ_get_pubkey(req));
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(ca_key,"ML-DSA-44")||EVP_PKEY_is_a(ca_key,"ML-DSA-65")||EVP_PKEY_is_a(ca_key,"ML-DSA-87")))
        md = EVP_sha256();
    if (!X509_sign(crt, ca_key, md)) die("X509_sign CA");
    return crt;
}

static void write_pems(EVP_PKEY *pkey, X509_REQ *req, X509 *crt, const char *basename) {
    ensure_cert_dir();
    char keypath[512], csrpath[512], crtpath[512];
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
        X509 *self = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(self), 1);
        X509_gmtime_adj(X509_get_notBefore(self), 0);
        X509_gmtime_adj(X509_get_notAfter(self), (long)60*60*24*DAYS_VALID);
        X509_set_subject_name(self, X509_REQ_get_subject_name(req));
        X509_set_issuer_name(self, X509_REQ_get_subject_name(req));
        X509_set_pubkey(self, X509_REQ_get_pubkey(req));
        const EVP_MD *md = NULL;
        EVP_PKEY *tmp = X509_REQ_get_pubkey(req);
        if (!(EVP_PKEY_is_a(tmp,"ML-DSA-44")||EVP_PKEY_is_a(tmp,"ML-DSA-65")||EVP_PKEY_is_a(tmp,"ML-DSA-87")))
            md = EVP_sha256();
        EVP_PKEY_free(tmp);
        if (!X509_sign(self, X509_REQ_get_pubkey(req), md)) die("self sign client");
        FILE *fc = fopen(crtpath, "wb"); if (!fc) die("open clientcrt");
        if (!PEM_write_X509(fc, self)) die("write clientcrt");
        fclose(fc);
        X509_free(self);
    } else {
        FILE *fc = fopen(crtpath, "wb"); if (!fc) die("open clientcrt");
        if (!PEM_write_X509(fc, crt)) die("write clientcrt");
        fclose(fc);
    }
    printf("Wrote %s, %s, %s\n", keypath, csrpath, crtpath);
}

static void print_x509_info(X509 *cert) {
    if (!cert) { printf("(no cert)\n"); return; }
    char *s = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *i = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("\n===== 📜 Certificate Info =====\n");
    printf("Subject: %s\nIssuer : %s\n", s, i);
    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (pk) {
        printf("Public Key Bits: %d\n", EVP_PKEY_bits(pk));
        printf("Algorithm      : %s\n", OBJ_nid2ln(EVP_PKEY_base_id(pk)));
        EVP_PKEY_free(pk);
    }
    const X509_ALGOR *sigalg; const ASN1_BIT_STRING *sig;
    X509_get0_signature(&sig, &sigalg, cert);
    if (sigalg && sigalg->algorithm) {
        char algname[128]; OBJ_obj2txt(algname, sizeof(algname), sigalg->algorithm, 1);
        printf("Signature Algo : %s\n", algname);
    }
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    printf("Validity:\n  Not Before: ");
    ASN1_TIME_print(bio, X509_get0_notBefore(cert));
    printf("\n  Not After : ");
    ASN1_TIME_print(bio, X509_get0_notAfter(cert));
    printf("\n===============================\n");
    OPENSSL_free(s); OPENSSL_free(i);
    BIO_free(bio);
}

static void run_client(int insecure, const char *groups_list, const char *server_ip) {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new");

    if (groups_list) {
        if (!SSL_CTX_set1_groups_list(ctx, groups_list)) {
            fprintf(stderr, "Warning: could not set groups list '%s'\n", groups_list);
        } else {
            printf("Using groups list: %s\n", groups_list);
        }
    }

    if (!insecure) {
        char cafile[512]; snprintf(cafile, sizeof(cafile), "%s/ca.crt", CERT_DIR);
        if (access(cafile, R_OK) == 0) {
            if (!SSL_CTX_load_verify_locations(ctx, cafile, NULL)) {
                fprintf(stderr, "Warning: could not load CA file %s\n", cafile);
            } else {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
                printf("Client will verify server cert using %s\n", cafile);
            }
        } else {
            printf("No CA found, but not in insecure mode: server verification will fail unless you provide CA\n");
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        printf("Client running in INSECURE mode (no server cert verification).\n");
    }

    char client_crt[512], client_key[512];
    snprintf(client_crt, sizeof(client_crt), "%s/client.crt", CERT_DIR);
    snprintf(client_key, sizeof(client_key), "%s/client.key", CERT_DIR);
    if (access(client_crt, R_OK) == 0 && access(client_key, R_OK) == 0) {
        SSL_CTX_use_certificate_file(ctx, client_crt, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket");
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(PORT);
    if (!server_ip) server_ip = "127.0.0.1";
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0) die("inet_pton");

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
        return;
    }
    printf("🔐 PQC TLS handshake successful!\n");

    X509 *srv = SSL_get_peer_certificate(ssl);
    if (srv) { print_x509_info(srv); X509_free(srv); }
    else printf("No server certificate presented\n");

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const char *cname = cipher ? SSL_CIPHER_get_name(cipher) : "Unknown";
    printf("Cipher suite: %s\n", cname);

    int gid = SSL_get_shared_group(ssl, 0);
    const char *gname = "unknown";
    if (gid > 0) {
        const char *tmp = SSL_group_to_name(ssl, gid);
        if (tmp) gname = tmp;
    }
    printf("KEX group: %s (id=%d)\n", gname, gid);

    char buf[4096]; int n = SSL_read(ssl, buf, sizeof(buf)-1);
    if (n > 0) { buf[n] = 0; printf("📨 Received: %s\n", buf); }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(0, NULL);

    int insecure = 0;
    const char *groups = NULL;
    const char *server_ip = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--insecure") == 0) insecure = 1;
        else if (strcmp(argv[i], "--groups") == 0 && i+1 < argc) groups = argv[++i];
        else if (strcmp(argv[i], "--server") == 0 && i+1 < argc) server_ip = argv[++i];
    }

    printf("PQC TLS Client\n1) Generate client key+CSR and sign via local CA (if present)\n2) Connect to server\nChoice: ");
    int c = 0; if (scanf("%d", &c) != 1) return 0;

    if (c == 1) {
        printf("Choose algo: 1) RSA 2) ML-DSA-44\nChoice: ");
        int a=0; if (scanf("%d", &a) != 1) return 0;
        const char *algo = (a == 2) ? "ML-DSA-44" : "RSA";
        ensure_cert_dir();
        EVP_PKEY *pkey = generate_key_by_name(algo);
        X509_REQ *req = create_csr(pkey, "client");

        EVP_PKEY *ca_key = NULL; X509 *ca_crt = NULL;
        int have_ca = load_ca(&ca_key, &ca_crt, "ca");
        X509 *signed_cert = NULL;
        if (have_ca) {
            signed_cert = sign_csr_with_ca(req, ca_key, ca_crt);
            write_pems(pkey, req, signed_cert, "client");
            EVP_PKEY_free(ca_key); X509_free(ca_crt); X509_free(signed_cert);
        } else {
            printf("No CA found in %s, self-signing client cert.\n", CERT_DIR);
            write_pems(pkey, req, NULL, "client");
        }
        X509_REQ_free(req); EVP_PKEY_free(pkey);
    } else if (c == 2) {
        run_client(insecure, groups, server_ip);
    } else {
        printf("Invalid choice\n");
    }

    return 0;
}
