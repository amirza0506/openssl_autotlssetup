#!/bin/bash
# =====================================================
#  🧬 PQC DEMO AUTOMATION TOOL v2
#  Author: kaliza + ChatGPT
#  Features: Interactive menu, loop, better UX, auto server/client run
# =====================================================

# ---------- CONFIG ----------
WORKDIR="$HOME/pqc_demo"
CA_DIR="$WORKDIR/ca"
SERVER_DIR="$WORKDIR/server"
CLIENT_DIR="$WORKDIR/client"
mkdir -p "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR"

# ---------- COLORS ----------
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

# ---------- ANIMATION ----------
loading() {
  local msg="$1"
  local frames="/-\|"
  echo -ne "\n${CYAN}$msg ${NC}"
  for i in {1..10}; do
    printf "\r${CYAN}$msg ${frames:i%${#frames}:1}${NC}"
    sleep 0.15
  done
  echo -ne "\r${CYAN}$msg ... done.${NC}\n"
}

finish_alert() {
  echo -e "\n${GREEN}==========================================${NC}"
  echo -e "${GREEN}✅  TASK COMPLETED SUCCESSFULLY!${NC}"
  echo -e "${GREEN}==========================================${NC}\n"
  sleep 1
}

error_exit() {
  echo -e "\n${RED}[✘] $1${NC}\n"
  read -p "Press Enter to return to main menu..."
}

pause_continue() {
  read -p "Press Enter to continue..."
}

# ---------- MENU FUNCTIONS ----------
choose_role() {
  clear
  echo -e "${YELLOW}Select Role:${NC}"
  echo "1) CA"
  echo "2) Server"
  echo "3) Client"
  echo "4) Exit"
  read -p "Enter choice [1-4]: " ROLE
}

choose_algo() {
  echo -e "\n${YELLOW}Select Algorithm:${NC}"
  echo "1) Classical (RSA/ECDSA)"
  echo "2) NIST PQC (ML-DSA / ML-KEM)"
  echo "3) Kaz (KAZ-DSA / KAZ-KEM)"
  read -p "Enter choice [1-3]: " ALGO
}

algo_preset() {
  case $ALGO in
    1) ALGO_NAME="RSA"; KEY_OPT="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
    2) ALGO_NAME="ML-DSA-44"; KEY_OPT="-algorithm ML-DSA-44" ;;
    3) ALGO_NAME="KAZ-DSA-3"; KEY_OPT="-algorithm KAZ-DSA-3" ;;
    *) error_exit "Invalid algorithm choice"; return 1 ;;
  esac
}

# ---------- ROLE ACTIONS ----------
generate_ca() {
  cd "$CA_DIR" || return
  loading "Generating CA key ($ALGO_NAME)"
  openssl genpkey $KEY_OPT -out ca.key || { error_exit "Failed to generate CA key"; return; }

  loading "Creating CA self-signed certificate"
  openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=${ALGO_NAME}-Root-CA" || { error_exit "Failed to create CA certificate"; return; }

  finish_alert
  echo -e "${CYAN}CA key and certificate saved in:${NC} $CA_DIR\n"
}

generate_server() {
  cd "$SERVER_DIR" || return
  loading "Generating server key ($ALGO_NAME)"
  openssl genpkey $KEY_OPT -out server.key || { error_exit "Failed to generate server key"; return; }

  loading "Creating server CSR"
  openssl req -new -key server.key -out server.csr -subj "/CN=pqc-server" || { error_exit "Failed to create server CSR"; return; }

  loading "Signing server certificate with CA"
  openssl x509 -req -in server.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out server.crt -days 365 || { error_exit "Failed to sign server certificate"; return; }

  finish_alert
  echo -e "${CYAN}Server certificate ready at:${NC} $SERVER_DIR"
}

generate_client() {
  cd "$CLIENT_DIR" || return
  loading "Generating client key ($ALGO_NAME)"
  openssl genpkey $KEY_OPT -out client.key || { error_exit "Failed to generate client key"; return; }

  loading "Creating client CSR"
  openssl req -new -key client.key -out client.csr -subj "/CN=pqc-client" || { error_exit "Failed to create client CSR"; return; }

  loading "Signing client certificate with CA"
  openssl x509 -req -in client.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out client.crt -days 3650 || { error_exit "Failed to sign client certificate"; return; }

  finish_alert
  echo -e "${CYAN}Client certificate ready at:${NC} $CLIENT_DIR"
}

run_server() {
  cd "$SERVER_DIR" || return
  if [[ ! -f server.crt || ! -f server.key ]]; then
    error_exit "Server certificate or key not found. Generate them first!"
    return
  fi
  loading "Launching PQC-enabled TLS server"
  echo -e "${GREEN}Running server... (Ctrl+C to stop)${NC}\n"
  openssl s_server -cert server.crt -key server.key -CAfile "$CA_DIR/ca.crt" -www -groups X25519MLKEM768
}

run_client() {
  cd "$CLIENT_DIR" || return
  if [[ ! -f client.crt || ! -f client.key ]]; then
    error_exit "Client certificate or key not found. Generate them first!"
    return
  fi
  read -p "Enter server IP (default: 127.0.0.1): " SERVER_IP
  SERVER_IP=${SERVER_IP:-127.0.0.1}
  loading "Connecting to TLS server at $SERVER_IP:4433"
  openssl s_client -connect "$SERVER_IP:4433" -CAfile "$CA_DIR/ca.crt" -groups X25519MLKEM768
}

# ---------- ACTION MENU ----------
server_menu() {
  echo -e "\n${YELLOW}Server Actions:${NC}"
  echo "1) Generate Server Certificate"
  echo "2) Run PQC Server"
  echo "3) Back to Main Menu"
  read -p "Choose action [1-3]: " ACTION
  case $ACTION in
    1) generate_server ;;
    2) run_server ;;
    3) return ;;
    *) error_exit "Invalid option" ;;
  esac
}

client_menu() {
  echo -e "\n${YELLOW}Client Actions:${NC}"
  echo "1) Generate Client Certificate"
  echo "2) Run PQC Client"
  echo "3) Back to Main Menu"
  read -p "Choose action [1-3]: " ACTION
  case $ACTION in
    1) generate_client ;;
    2) run_client ;;
    3) return ;;
    *) error_exit "Invalid option" ;;
  esac
}

# ---------- MAIN LOOP ----------
while true; do
  choose_role
  case $ROLE in
    1)
      choose_algo
      algo_preset || continue
      generate_ca
      ;;
    2)
      choose_algo
      algo_preset || continue
      server_menu
      ;;
    3)
      choose_algo
      algo_preset || continue
      client_menu
      ;;
    4)
      echo -e "\n${GREEN}Goodbye! 👋${NC}\n"
      exit 0
      ;;
    *)
      error_exit "Invalid role selection"
      ;;
  esac
  pause_continue
done
