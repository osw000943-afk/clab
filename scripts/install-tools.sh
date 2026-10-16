#!/usr/bin/env bash
# install-tools.sh - Cai dat cac scanner bo sung cho clab
# Chay tren server Debian/Ubuntu. Tu dong chay thu tu de tranh het RAM 1GB.
set -euo pipefail

echo "== Cap nhat paket he thong =="
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y nmap nikto whatweb sqlmap trivy tshark joomscan feroxbuster git curl wget
else
  echo "He thong khong phai Debian/Ubuntu. Vui long cai nmap nikto whatweb sqlmap trivy tshark joomscan feroxbuster bang tay."
fi

echo "== Cai Go tools (mot luc mot, tranh het RAM) =="
export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH 2>/dev/null || echo $HOME/go)/bin
if command -v go >/dev/null 2>&1; then
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install github.com/OJ/gobuster/v3@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/hahwul/dalfox/v2@latest
  go install github.com/google/osv-scanner/cmd/osv-scanner@latest
  go install github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest
else
  echo "Chua co go. Cai go tu https://go.dev/dl/ sau do chay lai script nay."
fi

echo "== Cai Python/pip tools =="
if command -v pip3 >/dev/null 2>&1; then
  pip3 install --break-system-packages dirsearch droopescan semgrep checkov || pip3 install dirsearch droopescan semgrep checkov
else
  echo "Chua co pip3."
fi

echo "== Cai Node tools =="
if command -v npm >/dev/null 2>&1; then
  npm install -g retire
else
  echo "Chua co npm."
fi

echo "== Xong =="
echo "Cac tool da cai: nmap nikto whatweb nikto sqlmap trivy tshark joomscan feroxbuster"
echo "Cac tool Go: nuclei subfinder naabu gobuster httpx dalfox osv-scanner gitleaks"
echo "Cac tool pip: dirsearch droopescan semgrep checkov"
echo "Cac tool npm: retire"
echo ""
echo "Lưu ý: ZAP, Burp (manual), Arachni (khong khuyen khich), w3af (da ngung) KHONG cai o day."
echo "Wazuh/OSSEC: can host giam sat rieng, khong cai trong trinh chinh cua clab (qua noc 1GB RAM)."
echo "VirusTotal/urlscan/BuiltWith/Safe Browsing: nhap API key o Settings -> Co ban (External keys)."
