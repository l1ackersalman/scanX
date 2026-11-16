#!/bin/bash

export PATH="$PATH:$HOME/go/bin"

# Fix for invalid working directory
if ! pwd &>/dev/null; then
    echo "[!] Current directory is invalid (possibly deleted). Switching to home directory..."
    cd ~ || { echo "[✘] Failed to change to home directory. Exiting."; exit 1; }
fi

# Start timing the script
start_time=$(date +%s)

# Help message
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 <domain>"
    exit 0
fi

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1
dir_name=$domain

# Check required tools
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "[!] Error: $1 is not installed. Please install it first."
        exit 1
    fi
}
for tool in crt subfinder assetfinder chaos dnsx ~/go/bin/httpx figlet jq; do
    check_tool "$tool"
done

# Handle output directory
if [ -d "$dir_name" ]; then
    echo "[!] Directory $dir_name already exists. Creating a new directory..."
    count=1
    while [ -d "${domain}-$(printf "%02d" $count)" ]; do
        ((count++))
    done
    dir_name="${domain}-$(printf "%02d" $count)"
fi

mkdir -p "$dir_name" || { echo "[✘] Failed to create directory. Exiting."; exit 1; }
cd "$dir_name" || { echo "[✘] Failed to cd into $dir_name. Exiting."; exit 1; }

# Log to file + terminal
exec > >(tee -a "../$dir_name/report.txt") 2>&1

# ========================[ RECON BLOCK ]========================

echo "[✔] Scanning..."

subfinder -d "$domain" -silent -json > subfinder.json
echo "[+] $(wc -l < subfinder.json) domains found from subfinder."

assetfinder --subs-only "$domain" | jq -Rs 'split("\n") | map(select(length > 0))' > assetfinder.json
echo "[+] $(jq length assetfinder.json) domains found from assetfinder."

chaos -d "$domain" -key 01691ef6-0ea0-4525-93fe-0f158d94ec16 -silent -json > chaos.json
echo "[+] $(wc -l < chaos.json) domains found from chaos."

crt -s -json "$domain" > crt.json
echo "[+] $(wc -l < crt.json) domains found from crt.sh."

# Merge all JSON results into alldomains.json (unique, sorted)
jq -s '[.[][]] | unique | sort' subfinder.json assetfinder.json chaos.json crt.json > alldomains.json
echo "[+] $(jq length alldomains.json) unique domains found."

# Create plain text list for dnsx/httpx input
jq -r '.[]' alldomains.json > alldomains.txt

dnsx -l alldomains.txt -silent -json -o live.json > /dev/null 2>&1
echo "[+] $(wc -l < live.json) live domains found."

# Extract live domains to plain text for httpx input
jq -r '.[]' live.json > live.txt 2>/dev/null || true

/home/insomniax/go/bin/httpx -sc -title -tech-detect -server -ip -cname -probe -silent -json -o httpx.json -l alldomains.txt > /dev/null 2>&1

echo "[✔] Scan completed for $domain."  2>/dev/null

end_time=$(date +%s)
elapsed=$((end_time - start_time))

hours=$((elapsed / 3600))
minutes=$(((elapsed % 3600) / 60))

echo -e "\n⏱️  Total Execution Time: ${hours}h ${minutes}m"
