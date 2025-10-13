#!/bin/bash
# =====================================================
#  🖥️ PQC DEMO: Server System
#  Author: kaliza + ChatGPT
# =====================================================

CA_DIR="$HOME/pqc_demo_ca"
WORKDIR="$HOME/pqc_demo_server"
mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit

GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; NC='\033[0m'

loading() {
  local msg="$1"
  local frames="/-\|"
  echo -ne "${CYAN}$msg ${NC}"
  for i in {1..8}; do
    printf "\r${CYAN}$msg ${frames:i%${#frames}:1}${NC}"
    sleep 0.15
  done
  echo -ne "\r${CYAN}$msg ... done.${NC}\n"
}

choose_algo() {
  echo -e "\n${YELLOW}Select Algorithm for Server:${NC}"
  echo "1) RSA (2048-bit)"
  echo "2) ML-DSA-44"
  echo "3) KAZ-DSA-3"
  read -p "Enter choice [1-3]: " CHOICE

  case $CHOICE in
    1) ALGO="RSA"; OPT="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
    2) ALGO="ML-DSA-44"; OPT="-algorithm ML-DSA-44" ;;
    3) ALGO="KAZ-DSA-3"; OPT="-algorithm KAZ-DSA-3" ;;
    *) echo -e "${RED}Invalid choice.${NC}"; return 1 ;;
  esac
}

generate_server() {
  choose_algo || return

  loading "Generating server key ($ALGO)"
  openssl genpkey $OPT -out server.key || { echo -e "${RED}❌ Failed to generate key${NC}"; return; }

  loading "Creating server CSR"
  openssl req -new -key server.key -out server.csr -subj "/CN=pqc-server"

  loading "Signing server certificate"
  openssl x509 -req -in server.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out server.crt -days 365

  echo -e "\n${GREEN}✅ Server certificate created successfully.${NC}"
  ls -l server.*
}

run_server() {
  if [[ ! -f server.crt || ! -f server.key ]]; then
    echo -e "${RED}No certificate found!${NC} Generate one first."
    return
  fi
  echo -e "\n${GREEN}Starting PQC TLS Server on port 4433...${NC}"
  echo -e "${CYAN}Press Ctrl+C to stop.${NC}\n"
  openssl s_server -cert server.crt -key server.key -CAfile "$CA_DIR/ca.crt" -www -groups X25519MLKEM768
}

echo -e "${YELLOW}1) Generate Server Certificate${NC}"
echo -e "${YELLOW}2) Run Server${NC}"
read -p "Enter choice [1-2]: " ACTION
case $ACTION in
  1) generate_server ;;
  2) run_server ;;
  *) echo "Invalid choice" ;;
esac
