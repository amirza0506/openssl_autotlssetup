#!/bin/bash
# =====================================================
#  🏛️ PQC DEMO: CA System
#  Author: kaliza + ChatGPT
# =====================================================

WORKDIR="$HOME/pqc_demo_ca"
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

generate_ca() {
  echo -e "\n${YELLOW}Select CA Algorithm:${NC}"
  echo "1) RSA (2048-bit)"
  echo "2) ML-DSA-44"
  echo "3) KAZ-DSA-3"
  read -p "Enter choice [1-3]: " CHOICE

  case $CHOICE in
    1) ALGO="RSA"; OPT="-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
    2) ALGO="ML-DSA-44"; OPT="-algorithm ML-DSA-44" ;;
    3) ALGO="KAZ-DSA-3"; OPT="-algorithm KAZ-DSA-3" ;;
    *) echo -e "${RED}Invalid choice.${NC}"; return ;;
  esac

  loading "Generating CA key ($ALGO)"
  openssl genpkey $OPT -out ca.key || { echo -e "${RED}❌ Failed${NC}"; return; }

  loading "Creating CA certificate"
  openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=${ALGO}-Root-CA"

  echo -e "\n${GREEN}✅ CA generated successfully!${NC}"
  echo -e "${CYAN}Files stored in:${NC} $WORKDIR"
  ls -l ca.*
}

generate_ca
