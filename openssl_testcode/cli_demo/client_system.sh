#!/bin/bash
# =====================================================
#  💻 PQC DEMO: Client System
#  Author: kaliza + ChatGPT
# =====================================================

CA_DIR="$HOME/pqc_demo_ca"
WORKDIR="$HOME/pqc_demo_client"
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
  echo -e "\n${YELLOW}Select Algorithm for Client:${NC}"
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

generate_client() {
  choose_algo || return

  loading "Generating client key ($ALGO)"
  openssl genpkey $OPT -out client.key || { echo -e "${RED}❌ Failed to generate key${NC}"; return; }

  loading "Creating client CSR"
  openssl req -new -key client.key -out client.csr -subj "/CN=pqc-client"

  loading "Signing client certificate"
  openssl x509 -req -in client.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out client.crt -days 3650

  echo -e "\n${GREEN}✅ Client certificate created successfully.${NC}"
  ls -l client.*
}

run_client() {
  if [[ ! -f client.crt || ! -f client.key ]]; then
    echo -e "${RED}No certificate found!${NC} Generate one first."
    return
  fi

  read -p "Enter server IP (default 127.0.0.1): " SERVER_IP
  SERVER_IP=${SERVER_IP:-127.0.0.1}

  echo -e "\n${CYAN}Connecting to $SERVER_IP:4433 ...${NC}"
  openssl s_client -connect "$SERVER_IP:4433" -CAfile "$CA_DIR/ca.crt" -groups X25519MLKEM768
}

echo -e "${YELLOW}1) Generate Client Certificate${NC}"
echo -e "${YELLOW}2) Run Client${NC}"
read -p "Enter choice [1-2]: " ACTION
case $ACTION in
  1) generate_client ;;
  2) run_client ;;
  *) echo "Invalid choice" ;;
esac
