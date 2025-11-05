#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
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

EVP_PKEY *generate_key(const char *algo);
EVP_PKEY *generate_kaz_key(void);

void die(const char *msg) {
    fprintf(stderr, "❌ %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

EVP_PKEY *generate_key(const char *algo)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (algo == NULL) return NULL;

    char nalgo[64];
    memset(nalgo, 0, sizeof(nalgo));
    strncpy(nalgo, algo, sizeof(nalgo)-1);
    for (char *p = nalgo; *p; ++p) *p = (char)toupper((unsigned char)*p);

    if (strcmp(nalgo, "KAZ") == 0) {
 
        return generate_kaz_key();
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, nalgo, NULL);
    if (ctx == NULL) {

        fprintf(stderr, "⚠️  Algorithm \"%s\" not available; falling back to RSA for compatibility.\n", algo);
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (ctx == NULL) {
            fprintf(stderr, "❌ Failed to create keygen context for RSA fallback.\n");
            return NULL;
        }
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_is_a(EVP_PKEY_CTX_get0_pkey(ctx), "RSA") == 1) {

        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    } else {

    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY *generate_kaz_key(void)
{
    fprintf(stderr, "ℹ️  \"kaz\" algorithm is reserved but not implemented yet.\n");
    return NULL;
}

X509_REQ *generate_csr(EVP_PKEY *pkey) {
    X509_REQ *req = X509_REQ_new();
    if (!req)
        die("Failed to allocate CSR");

    X509_NAME *name = X509_NAME_new();
    // X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"MY", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"PQC Server Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"TLS_BIT", -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);

    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey, "ML-DSA-44") || EVP_PKEY_is_a(pkey, "ML-DSA-65") || EVP_PKEY_is_a(pkey, "ML-DSA-87")))
        md = EVP_sha256();

    if (!X509_REQ_sign(req, pkey, md))
        die("Failed to sign CSR");

    X509_NAME_free(name);
    return req;
}


X509 *sign_csr_with_ca(X509_REQ *req, EVP_PKEY *ca_key, X509 *ca_crt) {
    X509 *crt = X509_new();
    if (!crt) die("Failed to create cert from CSR");

    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 60L * 60L * 24L * DAYS_VALID);

    X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(crt, X509_REQ_get_subject_name(req));

    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(crt, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    if (!X509_sign(crt, ca_key, EVP_sha256()))
        die("Signing CSR with CA failed");

    return crt;
}

void generate_server_cert(const char *algo)
{
    EVP_PKEY *pkey = generate_key(algo);
    if (pkey == NULL) {
        fprintf(stderr, "❌ Failed to generate key for algorithm \"%s\". Aborting certificate creation.\n", algo);
        return;
    }

    X509 *crt = X509_new();
    if (!crt) {
        fprintf(stderr, "❌ Failed to allocate X509 certificate.\n");
        EVP_PKEY_free(pkey);
        return;
    }

    /* Serial, validity */
    if (!ASN1_INTEGER_set(X509_get_serialNumber(crt), 1)) {
        fprintf(stderr, "❌ Failed to set certificate serial.\n");
    }
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 31536000L); /* ~1 year */

    if (!X509_set_pubkey(crt, pkey)) {
        fprintf(stderr, "❌ Failed to set public key on certificate.\n");
    }

    X509_NAME *name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"MY", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"PTPKM_PQC_TLS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"TLS Server", -1, -1, 0);

    X509_set_issuer_name(crt, name);

    if (!X509_sign(crt, pkey, EVP_sha256())) {
        fprintf(stderr, "❌ Failed to sign certificate.\n");
    }

    if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        X509_free(crt);
        EVP_PKEY_free(pkey);
        return;
    }

    /* Write files */
    char keypath[512], crtpath[512];
    snprintf(keypath, sizeof(keypath), "%s/server.key", CERT_DIR);
    snprintf(crtpath, sizeof(crtpath), "%s/server.crt", CERT_DIR);

    FILE *fk = fopen(keypath, "wb");
    if (!fk) {
        perror("fopen key");
        X509_free(crt);
        EVP_PKEY_free(pkey);
        return;
    }
    if (!PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "❌ Failed to write private key to %s\n", keypath);
    }
    fclose(fk);

    FILE *fc = fopen(crtpath, "wb");
    if (!fc) {
        perror("fopen cert");
        X509_free(crt);
        EVP_PKEY_free(pkey);
        return;
    }
    if (!PEM_write_X509(fc, crt)) {
        fprintf(stderr, "❌ Failed to write certificate to %s\n", crtpath);
    }
    fclose(fc);

    printf("✅ Server certificate generated (algorithm requested: %s)\n", algo);
    EVP_PKEY_free(pkey);
    X509_free(crt);
}

void generate_server_cert_crs(const char *algo){
    EVP_PKEY *pkey = generate_key(algo);

    X509_REQ *req = generate_csr(pkey);

    /* Save key and CSR */
    char keypath[256], csrpath[256], crtpath[256];
    snprintf(keypath, sizeof(keypath), "%s/%s.key", CERT_DIR);
    snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", CERT_DIR);
    snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", CERT_DIR);

    FILE *fk = fopen(keypath, "wb");
    PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fk);

    FILE *fr = fopen(csrpath, "wb");
    PEM_write_X509_REQ(fr, req);
    fclose(fr);

    printf("✅ Generated key and CSR for %s\n");

    /* Step 3: Load CA files */
    FILE *fca = fopen(CERT_DIR "/ca_mldsa44.crt", "rb");
    FILE *fca_key = fopen(CERT_DIR "/ca_mldsa44.key", "rb");
    if (!fca || !fca_key)
        die("CA certificate or key missing in ./certs");

    X509 *ca_crt = PEM_read_X509(fca, NULL, NULL, NULL);
    EVP_PKEY *ca_key = PEM_read_PrivateKey(fca_key, NULL, NULL, NULL);
    fclose(fca);
    fclose(fca_key);

    /* Step 4: Sign CSR with CA */
    X509 *crt = sign_csr_with_ca(req, ca_key, ca_crt);

    FILE *fc = fopen(crtpath, "wb");
    PEM_write_X509(fc, crt);
    fclose(fc);

    printf("✅ Certificate signed by CA: %s\n", crtpath);

    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    X509_free(crt);
    X509_free(ca_crt);
    EVP_PKEY_free(ca_key);
}

void run_server(void)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sock = -1, client = -1;
    struct sockaddr_in addr;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_init_ssl(0, NULL);
#else
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
#endif

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "❌ Failed to create SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    if (access(CERT_DIR "/server.crt", R_OK) != 0 || access(CERT_DIR "/server.key", R_OK) != 0) {
        fprintf(stderr, "❌ Certificate or key not found in %s. Generate them first.\n", CERT_DIR);
        SSL_CTX_free(ctx);
        return;
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_DIR "/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, CERT_DIR "/server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "❌ Failed to load certificate or private key.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); SSL_CTX_free(ctx); return; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    printf("🟢 Server listening on port %d...\n", PORT);

    client = accept(sock, NULL, NULL);
    if (client < 0) {
        perror("accept");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "❌ SSL_new failed.\n");
        ERR_print_errors_fp(stderr);
        close(client);
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "❌ TLS handshake failed.\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("🔐 TLS handshake successful!\n");
        const char *msg = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello TLS\n";
        SSL_write(ssl, msg, (int)strlen(msg));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
}

int main(void)
{
    printf("1) Generate server certificate\n2) Run server\nChoice: ");
    int c = 0;
    if (scanf("%d", &c) != 1) return 1;

    if (c == 1) {
        printf("Select Algorithm:\n1) RSA\n2) ML-DSA-44\n3) KAZ (reserved)\n> ");
        int a = 0;
        if (scanf("%d", &a) != 1) return 1;
        switch (a) {
            case 1:
                generate_server_cert("RSA");
                break;
            case 2:
                generate_server_cert_crs("ML-DSA-44");
                break;
            case 3: 
                generate_server_cert("KAZ");
                break;
            default:
                fprintf(stderr, "Invalid selection\n");
                break;
        }
    } else if (c == 2) {
        run_server();
    } else {
        fprintf(stderr, "Invalid choice\n");
    }

    return 0;
}
