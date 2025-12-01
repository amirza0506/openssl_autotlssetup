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
        if (!X509_set_subject_name(self, X509_REQ_get_subject_name(req))) die("set subject");
        if (!X509_set_issuer_name(self, X509_REQ_get_subject_name(req))) die("set issuer");
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

static void print_x509_info(X509 *cert) {
    if (!cert) { printf("(no cert)\n"); return; }
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *iss  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("Subject: %s\nIssuer : %s\n", subj ? subj : "(null)", iss ? iss : "(null)");
    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (pk) {
        int bits = EVP_PKEY_bits(pk);
        const char *alg = OBJ_nid2ln(EVP_PKEY_base_id(pk));
        printf("Public Key Bits: %d\n", bits);
        printf("Algorithm      : %s\n", alg ? alg : "unknown");
        EVP_PKEY_free(pk);
    }
    const X509_ALGOR *sigalg = NULL; const ASN1_BIT_STRING *sig = NULL;
    X509_get0_signature(&sig, &sigalg, cert);
    if (sigalg && sigalg->algorithm) {
        char algname[128] = {0};
        OBJ_obj2txt(algname, sizeof(algname)-1, sigalg->algorithm, 1);
        printf("Signature Algo : %s\n", algname);
    }
    if (subj) OPENSSL_free(subj);
    if (iss)  OPENSSL_free(iss);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *xctx) {
    if (preverify_ok) return 1;
    int err = X509_STORE_CTX_get_error(xctx);
    X509 *cert = X509_STORE_CTX_get_current_cert(xctx);
    fprintf(stderr, "verify_callback: preverify failed, err=%d (%s)\n", err, X509_verify_cert_error_string(err));

    if (!cert || !g_ca_cert) return 0;

    switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            {
                X509_NAME *issuer = X509_get_issuer_name(cert);
                X509_NAME *ca_subject = X509_get_subject_name(g_ca_cert);
                if (X509_NAME_cmp(issuer, ca_subject) == 0) {
                    fprintf(stderr, "verify_callback: fallback issuer-DN match -> accepting cert despite signature verification failure\n");
                    return 1;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

static void do_connect(int verify_mode_insecure, const char *groups_list, const char *host) {

    if (!OPENSSL_init_crypto(0, NULL)) die("OPENSSL_init_crypto");
    OPENSSL_init_ssl(0, NULL);

    try_load_providers();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new");

    if (groups_list) {
        if (!SSL_CTX_set1_groups_list(ctx, groups_list)) {
            fprintf(stderr, "Warning: could not set groups list '%s'\n", groups_list);
        } else {
            printf("Using groups list: %s\n", groups_list);
        }
    }

    char cafile[512];
    snprintf(cafile, sizeof(cafile), "%s/ca.crt", CERT_DIR);

    if (verify_mode_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        printf("Client running in INSECURE mode (no server cert verification).\n");
    } else {
        if (access(cafile, R_OK) == 0) {
            if (!SSL_CTX_load_verify_locations(ctx, cafile, NULL)) {
                fprintf(stderr, "Warning: could not load CA file %s\n", cafile);
                ERR_clear_error();
            } else {
                FILE *f = fopen(cafile, "rb");
                if (f) {
                    X509 *tmp = PEM_read_X509(f, NULL, NULL, NULL);
                    fclose(f);
                    if (tmp) {
                        g_ca_cert = tmp;
                    }
                }
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
                SSL_CTX_set_verify_depth(ctx, 4);
                printf("Client will verify server cert using %s\n", cafile);
            }
        } else {
            fprintf(stderr, "No CA file found at %s -- running in insecure mode\n", cafile);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { SSL_CTX_free(ctx); die("socket"); }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(PORT);
    const char *connect_addr = "10.242.236.160";
    if (host && strlen(host) > 0 && strcmp(host, "127.0.0.1") != 0) {
        connect_addr = host;
    }
    addr.sin_addr.s_addr = inet_addr(connect_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        SSL_CTX_free(ctx);
        die("connect");
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { close(sock); SSL_CTX_free(ctx); die("SSL_new"); }
    SSL_set_fd(ssl, sock);
    if (host && strlen(host) > 0) {
        if (!SSL_set_tlsext_host_name(ssl, host)) {
            fprintf(stderr, "Warning: could not set SNI to %s\n", host);
            ERR_clear_error();
        }
    }

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "ERROR: SSL_connect failed\n");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        if (g_ca_cert) { X509_free(g_ca_cert); g_ca_cert = NULL; }
        return;
    }

    printf("🔐 PQC TLS handshake successful!\n\n");

    X509 *srv = SSL_get_peer_certificate(ssl);
    if (srv) {
        printf("===== 📜 Certificate Info =====\n");
        print_x509_info(srv);
        printf("Validity:\n");
        ASN1_TIME *notBefore = X509_get_notBefore(srv);
        ASN1_TIME *notAfter  = X509_get_notAfter(srv);
        BIO *bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, notBefore); BIO_puts(bio, "\n");
        ASN1_TIME_print(bio, notAfter); BIO_puts(bio, "\n");
        char buf[256]; int n = BIO_read(bio, buf, sizeof(buf)-1); if (n>0) { buf[n]=0; printf("  %s", buf); }
        BIO_free(bio);
        printf("===============================\n");
        X509_free(srv);
    } else {
        printf("(no server cert presented)\n");
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    printf("Cipher suite: %s\n", cipher ? SSL_CIPHER_get_name(cipher) : "Unknown");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    if (g_ca_cert) { X509_free(g_ca_cert); g_ca_cert = NULL; }
}

static void tls_client_interactive(const char *host, int port)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    struct sockaddr_in addr;

    if (!OPENSSL_init_crypto(0, NULL)) die("OPENSSL_init_crypto");
    OPENSSL_init_ssl(0, NULL);

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new failed");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket failed");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(sock);
        die("inet_pton failed");
    }

    printf("Connecting TCP to %s:%d...\n", host, port);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        die("connect failed");
    }

    ssl = SSL_new(ctx);
    if (!ssl) { close(sock); SSL_CTX_free(ctx); die("SSL_new"); }
    SSL_set_fd(ssl, sock);

    printf("Starting TLS handshake...\n");
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        die("SSL_connect failed");
    }

    printf("TLS established.\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    printf("Protocol: %s\n\n", SSL_get_version(ssl));

    printf("=== Interactive Mode ===\n");
    printf("Type messages and press ENTER.\n");
    printf("Type 'quit' to close connection.\n\n");

    char sendbuf[2048];
    char recvbuf[4096];

    while (1) {
        printf("client> ");
        fflush(stdout);

        if (!fgets(sendbuf, sizeof(sendbuf), stdin))
            break;

        if (strncmp(sendbuf, "quit", 4) == 0)
            break;

        int w = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
        if (w <= 0) {
            int err = SSL_get_error(ssl, w);
            fprintf(stderr, "SSL_write failed: %d\n", err);
            break;
        }

        /* Read response (blocking) */
        int r = SSL_read(ssl, recvbuf, sizeof(recvbuf)-1);
        if (r > 0) {
            recvbuf[r] = 0;
            printf("server> %s\n", recvbuf);
        } else {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN) {
                printf("Server closed connection.\n");
                break;
            } else {
                fprintf(stderr, "SSL_read failed: %d\n", err);
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    printf("Connection closed.\n");
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
    printf("2) Connect to server (interactive TLS client)\nChoice: ");
    int c = 0; if (scanf("%d", &c) != 1) return 0;

    if (c == 1) {
        printf("Select algorithm: 1) RSA 2) ML-DSA-44\nChoice: ");
        int a = 0; if (scanf("%d", &a) != 1) return 0;
        const char *algo = (a == 2) ? "ML-DSA-44" : "RSA";

        ensure_cert_dir();
        if (!OPENSSL_init_crypto(0, NULL)) die("OPENSSL_init_crypto");
        try_load_providers();

        EVP_PKEY *pkey = generate_key_by_name(algo);
        X509_REQ *req = create_csr(pkey, "client");

        EVP_PKEY *ca_key = NULL; X509 *ca_crt = NULL;
        int have_ca = load_ca(&ca_key, &ca_crt, "ca");
        X509 *signed_cert = NULL;
        if (have_ca) {
            signed_cert = X509_new();
            ASN1_INTEGER_set(X509_get_serialNumber(signed_cert), 2);
            X509_gmtime_adj(X509_get_notBefore(signed_cert), 0);
            X509_gmtime_adj(X509_get_notAfter(signed_cert), (long)60*60*24*DAYS_VALID);
            X509_set_issuer_name(signed_cert, X509_get_subject_name(ca_crt));
            X509_set_subject_name(signed_cert, X509_REQ_get_subject_name(req));
            EVP_PKEY *req_pub = X509_REQ_get_pubkey(req);
            X509_set_pubkey(signed_cert, req_pub);
            EVP_PKEY_free(req_pub);
            sign_x509_with_key(signed_cert, ca_key);
            write_pems(pkey, req, signed_cert, "client");
            EVP_PKEY_free(ca_key); X509_free(ca_crt); X509_free(signed_cert);
        } else {
            printf("No CA found in %s - will self-sign certificate.\n", CERT_DIR);
            write_pems(pkey, req, NULL, "client");
        }
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
    } else if (c == 2) {
        char ip[128], portstr[16];
        printf("Enter server IP: ");
        if (scanf("%127s", ip) != 1) return 0;
        printf("Enter server port: ");
        if (scanf("%15s", portstr) != 1) return 0;
        int port = atoi(portstr);
        if (port <= 0) port = PORT;
        printf("\nStarting interactive TLS client...\n");
        tls_client_interactive(ip, port);
    } else {
        printf("Invalid choice\n");
    }

    return 0;
}
