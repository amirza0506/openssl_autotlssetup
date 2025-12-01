#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

static void run_server(int verify_mode_insecure, const char *groups_list) {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new");

    if (groups_list) {
        if (!SSL_CTX_set1_groups_list(ctx, groups_list)) {
            fprintf(stderr, "Warning: could not set groups list '%s'\n", groups_list);
        } else {
            printf("Using groups list: %s\n", groups_list);
        }
    }

    char srv_crt[512], srv_key[512];
    snprintf(srv_crt, sizeof(srv_crt), "%s/server.crt", CERT_DIR);
    snprintf(srv_key, sizeof(srv_key), "%s/server.key", CERT_DIR);

    if (access(srv_crt, R_OK) != 0 || access(srv_key, R_OK) != 0) die("server cert/key missing - generate first");

    if (SSL_CTX_use_certificate_file(ctx, srv_crt, SSL_FILETYPE_PEM) <= 0) die("SSL_CTX_use_certificate_file");
    if (SSL_CTX_use_PrivateKey_file(ctx, srv_key, SSL_FILETYPE_PEM) <= 0) die("SSL_CTX_use_PrivateKey_file");

    if (!SSL_CTX_check_private_key(ctx)) {
        die("Server certificate and private key do NOT match (SSL_CTX_check_private_key failed)");
    }

    if (verify_mode_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        printf("Server running in INSECURE verify mode (no peer cert verification).\n");
    } else {
        char cafile[512]; snprintf(cafile, sizeof(cafile), "%s/ca.crt", CERT_DIR);
        if (access(cafile, R_OK) == 0) {
            if (!SSL_CTX_load_verify_locations(ctx, cafile, NULL)) {
                fprintf(stderr, "Warning: could not load CA file %s\n", cafile);
            } else {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
                printf("Server will verify client certs using %s\n", cafile);
            }
        } else {
            printf("No CA found on server; server will not require client certs by default.\n");
        }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket");
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(PORT); addr.sin_addr.s_addr = INADDR_ANY;
    int on = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(sock, 1) < 0) die("listen");
    printf("Server listening on port %d\n", PORT);

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) {
            perror("accept");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client);
            continue;
        }
        printf("🔐 TLS handshake successful (server)\n");

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

        X509 *srvcert = SSL_CTX_get0_certificate(ctx);
        if (srvcert) {
            printf("Server cert info:\n");
            print_x509_info(srvcert);
        }

        printf("Entering secure echo session with client.\n");
        char buf[4096];
        int readres;
        while ((readres = SSL_read(ssl, buf, sizeof(buf)-1)) > 0) {
            buf[readres] = 0;
            printf("Received: %s", buf);
            // Respond back to client
            if (SSL_write(ssl, buf, readres) <= 0) {
                break;
            }
        }
        printf("Client disconnected or SSL_read failed.\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(0, NULL);

    int insecure = 0;
    const char *groups = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--insecure") == 0) insecure = 1;
        else if (strcmp(argv[i], "--groups") == 0 && i+1 < argc) { groups = argv[++i]; }
    }

    printf("PQC TLS Server (simple demo)\n");
    printf("1) Generate server key+CSR and sign with local CA (if present)\n2) Run server\nChoice: ");
    int c = 0; if (scanf("%d", &c) != 1) return 0;

    if (c == 1) {
        printf("Select algorithm: 1) RSA 2) ML-DSA-44\nChoice: ");
        int a = 0; if (scanf("%d", &a) != 1) return 0;
        const char *algo = (a == 2) ? "ML-DSA-44" : "RSA";

        ensure_cert_dir();
        EVP_PKEY *pkey = generate_key_by_name(algo);
        X509_REQ *req = create_csr(pkey, "server");

        EVP_PKEY *ca_key = NULL; X509 *ca_crt = NULL;
        int have_ca = load_ca(&ca_key, &ca_crt, "ca");
        X509 *signed_cert = NULL;
        if (have_ca) {
            signed_cert = sign_csr_with_ca(req, ca_key, ca_crt);
            write_pems(pkey, req, signed_cert, "server");
            EVP_PKEY_free(ca_key); X509_free(ca_crt); X509_free(signed_cert);
        } else {
            printf("No CA found in %s - will self-sign certificate.\n", CERT_DIR);
            write_pems(pkey, req, NULL, "server");
        }
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
    } else if (c == 2) {
        run_server(insecure, groups);
    } else {
        printf("Invalid choice\n");
    }
    return 0;
}
