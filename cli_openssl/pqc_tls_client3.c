 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <sys/stat.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <sys/socket.h>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 #include <openssl/pem.h>
 #include <openssl/x509.h>
 #define CERT_DIR "./certs"
 #define PORT 4443
 #define DAYS_VALID 365
 
 static void die(const char *msg) {
     fprintf(stderr, "❌ %s\n", msg);
     ERR_print_errors_fp(stderr);
     exit(EXIT_FAILURE);
 }

 static const char *friendly_alg_name(EVP_PKEY *pkey) {
     if (!pkey) return "Unknown";
     int base = EVP_PKEY_base_id(pkey);
     const char *n = OBJ_nid2ln(base);
     if (n && strcmp(n, "undefined") != 0) return n;
     if (EVP_PKEY_is_a(pkey, "ML-DSA-44")) return "ML-DSA-44 (PQC)";
     if (EVP_PKEY_is_a(pkey, "ML-DSA-65")) return "ML-DSA-65 (PQC)";
     if (EVP_PKEY_is_a(pkey, "ML-DSA-87")) return "ML-DSA-87 (PQC)";
     return "Unknown/PQC";
 }
 
 static void print_certificate_info(X509 *cert) {
     if (!cert) { printf("No certificate\n"); return; }
     char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
     char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
     printf("\n📜 === Server Certificate ===\n");
     printf("Subject: %s\nIssuer : %s\n", subj ? subj : "(nil)", issuer ? issuer : "(nil)");
 
     EVP_PKEY *pub = X509_get_pubkey(cert);
     if (pub) {
         printf("Public Key Bits: %d\n", EVP_PKEY_bits(pub));
         printf("Algorithm      : %s\n", friendly_alg_name(pub));
         EVP_PKEY_free(pub);
     }
 
     const ASN1_BIT_STRING *sig = NULL;
     const X509_ALGOR *alg = NULL;
     X509_get0_signature(&sig, &alg, cert);
     if (alg) {
         char oidbuf[256];
         OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg->algorithm, 1);
         printf("Signature OID  : %s\n", oidbuf);
     }
 
     BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
     printf("Validity:\n  Not Before: ");
     ASN1_TIME_print(bio, X509_get0_notBefore(cert));
     printf("\n  Not After : ");
     ASN1_TIME_print(bio, X509_get0_notAfter(cert));
     printf("\n=============================\n\n");
     BIO_free(bio);
     OPENSSL_free(subj); OPENSSL_free(issuer);
 }

 static EVP_PKEY *generate_key(const char *algo) {
     EVP_PKEY *pkey = NULL;
     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
     if (!ctx) {
         fprintf(stderr, "⚠️  Algorithm %s not available — using RSA\n", algo);
         ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
         if (!ctx) die("EVP_PKEY_CTX_new_from_name failed");
     }
     if (EVP_PKEY_keygen_init(ctx) <= 0) die("EVP_PKEY_keygen_init");
     if (strcasecmp(algo, "RSA") == 0) EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
     if (EVP_PKEY_generate(ctx, &pkey) <= 0) die("EVP_PKEY_generate failed");
     EVP_PKEY_CTX_free(ctx);
     return pkey;
 }

 static void generate_client_cert_via_ca(const char *algo) {
     if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) die("mkdir certs");
     EVP_PKEY *pkey = generate_key(algo);
     X509_REQ *req = X509_REQ_new();
     X509_NAME *name = X509_NAME_new();
     X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"client", -1, -1, 0);
     X509_REQ_set_subject_name(req, name);
     X509_REQ_set_pubkey(req, pkey);
 
     const EVP_MD *md = EVP_sha256();
     if (!X509_REQ_sign(req, pkey, md)) {
         ERR_print_errors_fp(stderr);
         die("X509_REQ_sign failed");
     }
 
     FILE *fk = fopen(CERT_DIR "/client.key", "wb");
     if (!fk) die("fopen client.key");
     if (!PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) die("PEM_write_PrivateKey");
     fclose(fk);
 
     FILE *fr = fopen(CERT_DIR "/client.csr", "wb");
     if (!fr) die("fopen client.csr");
     if (!PEM_write_X509_REQ(fr, req)) die("PEM_write_X509_REQ");
     fclose(fr);
     printf("✅ Generated client key & CSR in %s\n", CERT_DIR);

     FILE *fca = fopen(CERT_DIR "/ca.crt", "rb");
     FILE *fca_key = fopen(CERT_DIR "/ca.key", "rb");
     if (!fca || !fca_key) {
         fprintf(stderr, "⚠️  CA files not present, you must sign client.csr manually using ca.key\n");
         if (fca) fclose(fca);
         if (fca_key) fclose(fca_key);
         EVP_PKEY_free(pkey);
         X509_REQ_free(req);
         return;
     }
 
     X509 *ca = PEM_read_X509(fca, NULL, NULL, NULL);
     EVP_PKEY *cakey = PEM_read_PrivateKey(fca_key, NULL, NULL, NULL);
     fclose(fca); fclose(fca_key);
     if (!ca || !cakey) die("Failed to load CA files");

     X509 *crt = X509_new();
     ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
     X509_gmtime_adj(X509_get_notBefore(crt), 0);
     X509_gmtime_adj(X509_get_notAfter(crt), 60L*60L*24L*DAYS_VALID);
     X509_set_issuer_name(crt, X509_get_subject_name(ca));
     X509_set_subject_name(crt, X509_REQ_get_subject_name(req));
     EVP_PKEY *req_pub = X509_REQ_get_pubkey(req);
     X509_set_pubkey(crt, req_pub);
     EVP_PKEY_free(req_pub);
 
     const EVP_MD *md_ca = EVP_sha256();
     if (!X509_sign(crt, cakey, md_ca)) {
         ERR_print_errors_fp(stderr);
         die("X509_sign (CA) failed");
     }
 
     FILE *fc = fopen(CERT_DIR "/client.crt", "wb");
     if (!fc) die("fopen client.crt");
     if (!PEM_write_X509(fc, crt)) die("PEM_write_X509 client.crt");
     fclose(fc);
     printf("✅ Signed client certificate saved to %s/client.crt\n", CERT_DIR);
 
     X509_free(crt); X509_free(ca); EVP_PKEY_free(cakey);
     EVP_PKEY_free(pkey); X509_REQ_free(req);
 }

 static void run_client_connect(void) {
     OPENSSL_init_ssl(0, NULL);
     SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
     if (!ctx) die("SSL_CTX_new");

     if (SSL_CTX_set1_groups_list(ctx, "MLKEM512") != 1)
         fprintf(stderr, "⚠️  MLKEM512 group not available — continuing with default groups.\n");

     if (SSL_CTX_load_verify_locations(ctx, CERT_DIR "/ca.crt", NULL) != 1) {
         fprintf(stderr, "⚠️  Could not load CA (certs/ca.crt). Server verification may fail.\n");
     }
     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
 
     if (access(CERT_DIR "/client.crt", R_OK) == 0 && access(CERT_DIR "/client.key", R_OK) == 0) {
         if (SSL_CTX_use_certificate_file(ctx, CERT_DIR "/client.crt", SSL_FILETYPE_PEM) <= 0)
             die("SSL_CTX_use_certificate_file (client)");
         if (SSL_CTX_use_PrivateKey_file(ctx, CERT_DIR "/client.key", SSL_FILETYPE_PEM) <= 0)
             die("SSL_CTX_use_PrivateKey_file (client)");
     } else {
         printf("⚠️  Client cert/key not found in %s — connecting without client cert (server may reject).\n", CERT_DIR);
     }
 
     int s = socket(AF_INET, SOCK_STREAM, 0);
     if (s < 0) die("socket");
     struct sockaddr_in addr;
     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET; addr.sin_port = htons(PORT);
     inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
 
     if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("connect");
 
     SSL *ssl = SSL_new(ctx);
     SSL_set_fd(ssl, s);
 
     if (SSL_connect(ssl) <= 0) {
         ERR_print_errors_fp(stderr);
         die("SSL_connect failed");
     }
     printf("🔐 TLS handshake completed (client)\n");

     X509 *srv = SSL_get_peer_certificate(ssl);
     if (srv) {
         print_certificate_info(srv);
         X509_free(srv);
     } else {
         printf("⚠️  No server certificate presented\n");
     }
 
     char buf[4096];
     int n = SSL_read(ssl, buf, sizeof(buf)-1);
     if (n > 0) {
         buf[n] = 0;
         printf("📨 Received (%d bytes):\n%s\n", n, buf);
     } else {
         int err = SSL_get_error(ssl, n);
         printf("SSL_read returned %d (error %d)\n", n, err);
     }

     SSL_shutdown(ssl);
     SSL_free(ssl);
     close(s);
     SSL_CTX_free(ctx);
 }
 
 int main(void) {
     printf("1) Generate client cert via CA (requires certs/ca.crt & certs/ca.key)\n");
     printf("2) Connect to mTLS server\n> ");
     int c = 0;
     if (scanf("%d", &c) != 1) return 1;
 
     if (c == 1) {
         generate_client_cert_via_ca("ML-DSA-44");
     } else if (c == 2) {
         run_client_connect();
     } else {
         printf("Invalid\n");
     }
     return 0;
 }
 