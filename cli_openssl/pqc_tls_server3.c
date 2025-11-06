#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void die(const char *m) { fprintf(stderr, "ERROR: %s\n", m); ERR_print_errors_fp(stderr); exit(1); }
static void ensure_cert_dir(void) { if (mkdir(CERT_DIR, 0755) != 0 && errno != EEXIST) { perror("mkdir"); exit(1);} }

static EVP_PKEY *generate_key_by_name(const char *name) {
    EVP_PKEY *pkey = NULL; EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (!ctx) { fprintf(stderr,"⚠ %s not available, fallback RSA\n",name); ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL); if (!ctx) die("ctx fail"); }
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("keygen_init");
    if (strcasecmp(name,"RSA")==0) EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,2048);
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) die("generate key failed");
    EVP_PKEY_CTX_free(ctx); return pkey;
}

static X509_REQ *create_csr(EVP_PKEY *pkey, const char *cn) {
    X509_REQ *req = X509_REQ_new(); if (!req) die("X509_REQ_new");
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)cn,-1,-1,0);
    X509_REQ_set_subject_name(req,name);
    X509_REQ_set_pubkey(req,pkey);
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(pkey,"ML-DSA-44")||EVP_PKEY_is_a(pkey,"ML-DSA-65")||EVP_PKEY_is_a(pkey,"ML-DSA-87")))
        md = EVP_sha256();
    if (!X509_REQ_sign(req,pkey,md)) die("X509_REQ_sign");
    X509_NAME_free(name); return req;
}

static int load_ca(EVP_PKEY **out_key, X509 **out_crt) {
    char kp[256], cp[256]; snprintf(kp,sizeof(kp),"%s/ca.key",CERT_DIR); snprintf(cp,sizeof(cp),"%s/ca.crt",CERT_DIR);
    FILE *fk = fopen(kp,"rb"); FILE *fc=fopen(cp,"rb");
    if(!fk||!fc){ if(fk)fclose(fk); if(fc)fclose(fc); return 0;}
    *out_key = PEM_read_PrivateKey(fk,NULL,NULL,NULL);
    *out_crt = PEM_read_X509(fc,NULL,NULL,NULL);
    fclose(fk); fclose(fc);
    return (*out_key && *out_crt) ? 1 : 0;
}

static X509 *sign_csr_with_ca(X509_REQ *req, EVP_PKEY *ca_key, X509 *ca_crt) {
    X509 *crt = X509_new(); if(!crt) die("X509_new");
    ASN1_INTEGER_set(X509_get_serialNumber(crt),1); X509_gmtime_adj(X509_get_notBefore(crt),0);
    X509_gmtime_adj(X509_get_notAfter(crt),(long)60*60*24*DAYS_VALID);
    X509_set_issuer_name(crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(crt, X509_REQ_get_subject_name(req));
    X509_set_pubkey(crt, X509_REQ_get_pubkey(req));
    const EVP_MD *md = NULL;
    if (!(EVP_PKEY_is_a(ca_key,"ML-DSA-44")||EVP_PKEY_is_a(ca_key,"ML-DSA-65")||EVP_PKEY_is_a(ca_key,"ML-DSA-87")))
        md = EVP_sha256();
    if (!X509_sign(crt, ca_key, md)) { X509_free(crt); die("X509_sign CA"); }
    return crt;
}

static void write_pems(EVP_PKEY *pkey, X509_REQ *req, X509 *crt, const char *base) {
    ensure_cert_dir();
    char kpath[256], crpath[256], csrpath[256];
    snprintf(kpath,sizeof(kpath),"%s/%s.key",CERT_DIR,base);
    snprintf(csrpath,sizeof(csrpath),"%s/%s.csr",CERT_DIR,base);
    snprintf(crpath,sizeof(crpath),"%s/%s.crt",CERT_DIR,base);
    FILE *fk=fopen(kpath,"wb"); if(!fk) die("open key"); PEM_write_PrivateKey(fk,pkey,NULL,NULL,0,NULL,NULL); fclose(fk);
    FILE *fc=fopen(csrpath,"wb"); if(!fc) die("open csr"); PEM_write_X509_REQ(fc,req); fclose(fc);
    if (!crt) {
        /* self sign */
        X509 *self = X509_new(); ASN1_INTEGER_set(X509_get_serialNumber(self),1);
        X509_gmtime_adj(X509_get_notBefore(self),0); X509_gmtime_adj(X509_get_notAfter(self),(long)60*60*24*DAYS_VALID);
        X509_set_subject_name(self, X509_REQ_get_subject_name(req)); X509_set_issuer_name(self, X509_REQ_get_subject_name(req));
        X509_set_pubkey(self, X509_REQ_get_pubkey(req));
        const EVP_MD *md=NULL; if(!(EVP_PKEY_is_a(pkey,"ML-DSA-44")||EVP_PKEY_is_a(pkey,"ML-DSA-65")||EVP_PKEY_is_a(pkey,"ML-DSA-87"))) md=EVP_sha256();
        if(!X509_sign(self,pkey,md)) die("self sign client");
        FILE *fcr=fopen(crpath,"wb"); if(!fcr) die("open client crt"); PEM_write_X509(fcr,self); fclose(fcr);
        X509_free(self);
    } else {
        FILE *fcr=fopen(crpath,"wb"); if(!fcr) die("open client crt"); PEM_write_X509(fcr,crt); fclose(fcr);
    }
    printf("Wrote %s, %s, %s\n", kpath, csrpath, crpath);
}

static void print_x509_info(X509 *cert) {
    if (!cert) { printf("(no cert)\n"); return; }
    char *s = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);
    char *i = X509_NAME_oneline(X509_get_issuer_name(cert),NULL,0);
    printf("Subject: %s\nIssuer:  %s\n", s, i);
    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (pk) { printf("Pubkey bits: %d\nAlgo: %s\n", EVP_PKEY_bits(pk), OBJ_nid2ln(EVP_PKEY_base_id(pk))); EVP_PKEY_free(pk); }
    const X509_ALGOR *sigalg; const ASN1_BIT_STRING *sig; X509_get0_signature(&sig,&sigalg,cert);
    char algname[128]; OBJ_obj2txt(algname,sizeof(algname), sigalg->algorithm, 1);
    printf("Signature alg: %s\n", algname);
    OPENSSL_free(s); OPENSSL_free(i);
}

static void run_client() {
    OPENSSL_init_ssl(0,NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); if(!ctx) die("SSL_CTX_new");
    SSL_CTX_set1_groups_list(ctx, "MLKEM512:X25519");

    char cafile[256]; snprintf(cafile,sizeof(cafile),"%s/ca.crt",CERT_DIR);
    if (access(cafile,R_OK)==0) {
        if (!SSL_CTX_load_verify_locations(ctx, cafile, NULL)) fprintf(stderr,"Warning: failed load CA\n");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        printf("No CA found, skipping server cert verify (insecure)\n");
    }

    char client_crt[256], client_key[256]; snprintf(client_crt,sizeof(client_crt),"%s/client.crt",CERT_DIR); snprintf(client_key,sizeof(client_key),"%s/client.key",CERT_DIR);
    if (access(client_crt,R_OK)==0 && access(client_key,R_OK)==0) {
        SSL_CTX_use_certificate_file(ctx, client_crt, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0}; addr.sin_family=AF_INET; addr.sin_port=htons(PORT);
    inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
    if (connect(sock,(struct sockaddr*)&addr,sizeof(addr))<0) { perror("connect"); SSL_CTX_free(ctx); return; }

    SSL *ssl = SSL_new(ctx); SSL_set_fd(ssl,sock);
    if (SSL_connect(ssl) <= 0) { ERR_print_errors_fp(stderr); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); return; }
    printf("TLS handshake OK\n");

    X509 *srv = SSL_get_peer_certificate(ssl);
    if (srv) { printf("===== Server certificate =====\n"); print_x509_info(srv); X509_free(srv); }
    else printf("No server certificate presented\n");

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const char *cname = cipher ? SSL_CIPHER_get_name(cipher) : "Unknown";
    printf("Cipher suite: %s\n", cname);

    int gid = SSL_get_shared_group(ssl, 0);
    const char *gname = "unknown";
    if (gid>0) { const char *tmp = SSL_group_to_name(ssl, gid); if (tmp) gname = tmp; }
    printf("KEX group: %s (id=%d)\n", gname, gid);

    char buf[4096]; int n = SSL_read(ssl, buf, sizeof(buf)-1);
    if (n>0) { buf[n]=0; printf("Received:\n%s\n", buf); }

    SSL_shutdown(ssl); SSL_free(ssl); close(sock); SSL_CTX_free(ctx);
}

int main(void) {
    OPENSSL_init_crypto(0,NULL);
    printf("PQC TLS Client\n1) Generate client key+CSR and sign via CA (if present)\n2) Connect to server\nChoice: ");
    int c=0; if (scanf("%d",&c)!=1) return 0;
    if (c==1) {
        printf("Choose algo: 1) RSA 2) ML-DSA-44\nChoice: ");
        int a=0; if (scanf("%d",&a)!=1) return 0;
        const char *algo = (a==2) ? "ML-DSA-44" : "RSA";
        ensure_cert_dir();
        EVP_PKEY *pkey = generate_key_by_name(algo);
        X509_REQ *req = create_csr(pkey, "client");
        EVP_PKEY *ca_key=NULL; X509 *ca_crt=NULL; X509 *signed_cert=NULL;
        if (load_ca(&ca_key, &ca_crt)) {
            signed_cert = sign_csr_with_ca(req, ca_key, ca_crt);
            write_pems(pkey, req, signed_cert, "client");
            EVP_PKEY_free(ca_key); X509_free(ca_crt); X509_free(signed_cert);
        } else {
            printf("No CA, self-signing client cert\n");
            write_pems(pkey, req, NULL, "client");
        }
        X509_REQ_free(req); EVP_PKEY_free(pkey);
    } else if (c==2) {
        run_client();
    } else printf("invalid\n");
    return 0;
}
