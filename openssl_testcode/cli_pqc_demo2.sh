#!/bin/bash
# =====================================================
#  PQC DEMO AUTOMATION SCRIPT
#  Author: kaliza + ChatGPT
#  Description: Interactive CA / Server / Client setup
# =====================================================

# ---------- CONFIG ----------
WORKDIR="$HOME/pqc_demo"
CA_DIR="$WORKDIR/ca"
SERVER_DIR="$WORKDIR/server"
CLIENT_DIR="$WORKDIR/client"
mkdir -p "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR"

# ---------- FUNCTIONS ----------
loading() {
  local msg="$1"
  echo -ne "\n$msg"
  for i in {1..3}; do
    echo -ne "."
    sleep 0.5
  done
  echo ""
}

alert() {
  echo -e "\n\033[1;32m[✔] $1\033[0m"
}

error() {
  echo -e "\n\033[1;31m[✘] $1\033[0m"
  exit 1
}

choose_role() {
  echo -e "\nSelect Role:"
  echo "1) CA"
  echo "2) Server"
  echo "3) Client"
  read -p "Enter choice [1-3]: " ROLE
}

choose_algo() {
  echo -e "\nSelect Algorithm:"
  echo "1) Classical (RSA/ECDSA)"
  echo "2) NIST PQC (ML-DSA / ML-KEM)"
  echo "3) Kaz (KAZ-DSA / KAZ-KEM)"
  read -p "Enter choice [1-3]: " ALGO
}

generate_ca() {
  cd "$CA_DIR" || exit
  case $ALGO in
    1) ALGO_NAME="RSA"; KEY_OPT="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
    2) ALGO_NAME="ML-DSA-44"; KEY_OPT="-algorithm ML-DSA-44" ;;
    3) ALGO_NAME="KAZ-DSA-3"; KEY_OPT="-algorithm KAZ-DSA-3" ;;
  esac

  loading "Generating CA key ($ALGO_NAME)"
  openssl genpkey $KEY_OPT -out ca.key || error "Failed to generate CA key"

  loading "Creating self-signed CA certificate"
  openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=${ALGO_NAME}-Root-CA" || error "Failed to create CA certificate"

  alert "CA setup complete at $CA_DIR"
}

generate_server() {
  cd "$SERVER_DIR" || exit
  case $ALGO in
    1) ALGO_NAME="RSA"; KEY_OPT="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
    2) ALGO_NAME="ML-DSA-44"; KEY_OPT="-algorithm ML-DSA-44" ;;
    3) ALGO_NAME="KAZ-DSA-3"; KEY_OPT="-algorithm KAZ-DSA-3" ;;
  esac

  loading "Generating server key ($ALGO_NAME)"
  openssl genpkey $KEY_OPT -out server.key || error "Failed to generate server key"

  loading "Creating server CSR"
  openssl req -new -key server.key -out server.csr -subj "/CN=pqc-server" || error "Failed to generate CSR"

  loading "Signing server certificate with CA"
  openssl x509 -req -in server.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out server.crt -days 365 || error "Failed to sign server certificate"

  alert "Server certificate ready at $SERVER_DIR"

  echo -e "\nRun server with:"
  echo "  openssl s_server -cert server.crt -key server.key -CAfile $CA_DIR/ca.crt -www -groups X25519MLKEM768"
}

generate_client() {
  cd "$CLIENT_DIR" || exit
  case $ALGO in
    1) ALGO_NAME="RSA"; KEY_OPT="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
    2) ALGO_NAME="ML-DSA-44"; KEY_OPT="-algorithm ML-DSA-44" ;;
    3) ALGO_NAME="KAZ-DSA-3"; KEY_OPT="-algorithm KAZ-DSA-3" ;;
  esac

  loading "Generating client key ($ALGO_NAME)"
  openssl genpkey $KEY_OPT -out client.key || error "Failed to generate client key"

  loading "Creating client CSR"
  openssl req -new -key client.key -out client.csr -subj "/CN=pqc-client" || error "Failed to create client CSR"

  loading "Signing client certificate with CA"
  openssl x509 -req -in client.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out client.crt -days 3650 || error "Failed to sign client certificate"

  alert "Client certificate ready at $CLIENT_DIR"

  echo -e "\nRun client test with:"
  echo "  openssl s_client -connect 127.0.0.1:4433 -CAfile $CA_DIR/ca.crt -groups X25519MLKEM768"
}

# ---------- MAIN ----------
clear
echo "==========================================="
echo "   🧬 PQC DEMO: CA / SERVER / CLIENT SETUP  "
echo "==========================================="

choose_role
choose_algo

case $ROLE in
  1) generate_ca ;;
  2) generate_server ;;
  3) generate_client ;;
  *) error "Invalid role selection" ;;
esac

alert "All done 🎉"
