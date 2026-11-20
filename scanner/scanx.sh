#!/bin/bash

export PATH="$PATH:$HOME/go/bin"

# ========================[ SETUP ]========================

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
for tool in crt subfinder assetfinder chaos dnsx ~/go/bin/httpx figlet; do
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

echo "[✔] Identifying Subdomains of $domain..."

subfinder -d "$domain" -silent > subfinder.txt
echo "[✔] Checking Live domains..."

assetfinder --subs-only "$domain" > assetfinder.txt
echo "[✔] Analyzing Technologies..."

chaos -d "$domain" -key "$CHAOS_API_KEY" -silent > chaos.txt
echo "[✔] Collecting Informations..."

crt -s "$domain" > crt.txt
echo "[✔] Deep Scanning..."

sort -u subfinder.txt assetfinder.txt chaos.txt crt.txt > alldomains.txt
rm -f subfinder.txt assetfinder.txt chaos.txt crt.txt
echo "[✔] Checking IP & CNAME records..."

dnsx -l alldomains.txt -silent -o live.txt > /dev/null 2>&1
echo "[✔] Final Evalution..."

/home/insomniax/go/bin/httpx -sc -title -tech-detect -ip -cname -probe -silent -json -o httpx.json -l live.txt > /dev/null 2>&1

# ========================[ FINISH ]========================

echo "[✔] Scan completed for $domain."  2>/dev/null

end_time=$(date +%s)
elapsed=$((end_time - start_time))

hours=$((elapsed / 3600))
minutes=$(((elapsed % 3600) / 60))

echo -e "\n⏱️  Total Execution Time: ${hours}h ${minutes}m"
