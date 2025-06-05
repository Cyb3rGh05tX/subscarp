#!/bin/bash

# 🛠️ Tool Metadata
TOOL_NAME="SubScarP"
VERSION="1.4"
AUTHOR="CyberGh05tX"
REPO_URL="https://github.com/Cyb3rGh05tX/subscarp"

# 🎨 Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ✨ ASCII Banner
show_banner() {
    echo -e "${PURPLE}"
    cat << "BANNER"
   _____       _       _____                 _____
  / ____|     | |     / ____|               |  __ \
 | (___  _   _| |__  | (___   ___ __ _ _ __| |__) |
  \___ \| | | | '_ \  \___ \ / __/ _` | '__|  ___/
  ____) | |_| | |_) | ____) | (_| (_| | |  | |
 |_____/ \__,_|_.__/ |_____/ \___\__,_|_|  |_|
BANNER
    echo -e "${NC}"
    echo -e "${CYAN}  [+] ${TOOL_NAME} v${VERSION}"
    echo -e "${YELLOW}  [+] Author: ${AUTHOR}"
    echo -e "${GREEN}  [+] Repo: ${REPO_URL}${NC}"
    echo -e "${CYAN}  [+] Started at: $(date +"%Y-%m-%d %H:%M:%S")${NC}\n"
}

# 📦 Required Tools
REQUIRED_TOOLS=(
    "subfinder"
    "assetfinder"
    "dnsx"
    "httpx"
    "waybackurls"
    "gau"
    "dnsgen"
    "jq"
)

# 🛠️ Tool Installer
install_tools() {
    echo -e "${GREEN}[+] Checking dependencies...${NC}"
    missing_count=0
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}  [!] Missing: ${YELLOW}$tool${NC}"
            ((missing_count++))
        fi
    done

    if [ "$missing_count" -gt 0 ]; then
        echo -e "\n${YELLOW}[!] $missing_count tools missing. Attempting to install...${NC}"
        
        # Install via package managers
        if ! command -v go &>/dev/null; then
            echo -e "${RED}  [!] Golang not found! Required for tool installation.${NC}"
            echo -e "${CYAN}  [→] Install manually: https://golang.org/doc/install${NC}"
            exit 1
        fi

        echo -e "${CYAN}[+] Installing missing tools via go install...${NC}"
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install github.com/tomnomnom/assetfinder@latest
        go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install github.com/tomnomnom/waybackurls@latest
        go install github.com/lc/gau/v2/cmd/gau@latest
        pip3 install dnsgen
        
        # Verify installations
        for tool in "${REQUIRED_TOOLS[@]}"; do
            if ! command -v "$tool" &>/dev/null; then
                echo -e "${RED}  [!] Failed to install: $tool${NC}"
                echo -e "${YELLOW}  [→] Manual installation required for $tool${NC}"
            fi
        done
        
        echo -e "\n${GREEN}[+] Installation attempt completed.${NC}"
        echo -e "${YELLOW}[!] Please restart your terminal/shell to refresh PATH${NC}"
        exit 0
    else
        echo -e "${GREEN}[✓] All dependencies are installed${NC}"
    fi
}

# ❓ Help Menu
show_help() {
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  ${GREEN}./subscanpro.sh -d example.com${NC}       # Scan single domain"
    echo -e "  ${GREEN}./subscanpro.sh -l domains.txt${NC}      # Scan multiple domains from file"
    echo -e "  ${GREEN}./subscanpro.sh -h${NC}                 # Show this help menu"
    echo -e "\n${YELLOW}Options:${NC}"
    echo -e "  ${CYAN}-d, --domain${NC}    Target domain"
    echo -e "  ${CYAN}-l, --list${NC}      File containing list of domains"
    echo -e "  ${CYAN}-h, --help${NC}      Show help"
    echo -e "\n${YELLOW}Examples:${NC}"
    echo -e "  ${GREEN}./subscanpro.sh -d google.com${NC}"
    echo -e "  ${GREEN}./subscanpro.sh -l mydomains.txt${NC}"
    exit 0
}

# ⏱️ Timer Functions
start_timer() {
    scan_start_time=$(date +%s)
}

show_elapsed_time() {
    current_time=$(date +%s)
    elapsed_seconds=$((current_time - scan_start_time))
    printf "%02d:%02d:%02d" $((elapsed_seconds/3600)) $((elapsed_seconds%3600/60)) $((elapsed_seconds%60))
}

# 🔍 Main Scanner Function
scan_domain() {
    local domain="$1"
    echo -e "\n${GREEN}[+] Scanning: ${YELLOW}$domain${NC} [Elapsed: $(show_elapsed_time)]"
    
    # Create domain directory
    domain_dir="$output_dir/$domain"
    mkdir -p "$domain_dir" || { echo -e "${RED}[!] Failed to create directory${NC}"; exit 1; }
    cd "$domain_dir" || exit

    # 1️⃣ Passive Enumeration
    echo -e "${CYAN}[→] Running passive tools...${NC}"
    subfinder -d "$domain" -silent -o subfinder.txt -t "$THREADS" 2>/dev/null
    assetfinder --subs-only "$domain" 2>/dev/null > assetfinder.txt

    # 2️⃣ Active Enumeration
    if [[ "$perform_bruteforce" == "yes" && -f "$WORDLIST" ]]; then
        echo -e "${CYAN}[→] Running bruteforce with: ${YELLOW}$WORDLIST${NC}"
        dnsx -d "$domain" -w "$WORDLIST" -silent -o brute.txt -t "$THREADS" 2>/dev/null
    else
        echo -e "${YELLOW}[→] Skipping bruteforce${NC}"
    fi

    # 3️⃣ Process Results
    cat *.txt 2>/dev/null | sort -u > "final-$domain.txt"
    count=$(wc -l < "final-$domain.txt")
    echo -e "${GREEN}[✓] Found ${YELLOW}$count${GREEN} subdomains [Elapsed: $(show_elapsed_time)]${NC}"
    cd ..
}

# Function to handle wordlist path input with tab completion
read_with_tab() {
    local prompt="$1"
    local reply

    # Enable readline for tab completion
    if [[ $- == *i* ]]; then
        read -e -p "$prompt" reply
    else
        read -p "$prompt" reply
    fi

    # Expand ~ to home directory
    reply="${reply/#\~/$HOME}"
    echo "$reply"
}

# ⚙️ Configuration
THREADS=50
output_dir="subscan_results_$(date +"%Y%m%d")"

# 🚀 Main Execution
show_banner
install_tools

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)
            domain="$2"
            shift 2
            ;;
        -l|--list)
            domain_list="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}[!] Invalid argument: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Validate input
if [[ -z "$domain" && -z "$domain_list" ]]; then
    echo -e "${RED}[!] No target specified!${NC}"
    show_help
    exit 1
fi

# Ask about bruteforce
perform_bruteforce="no"
WORDLIST=""

echo -e "${CYAN}[?] Do you want to perform bruteforce scanning? (yes/no)${NC}"
read -p "  Your choice: " perform_bruteforce

if [[ "$perform_bruteforce" =~ ^[yY]|[yY][eE][sS]$ ]]; then
    perform_bruteforce="yes"
    while true; do
        echo -e "${CYAN}[?] Enter path to your wordlist (Copy wordlist path and past here):${NC}"
        WORDLIST=$(read_with_tab "  Wordlist path: ")
        
        if [[ -z "$WORDLIST" ]]; then
            # Try default wordlist if user pressed Enter
            WORDLIST="/usr/share/wordlists/rockyou.txt"
            if [[ -f "$WORDLIST" ]]; then
                echo -e "${YELLOW}[→] Using default wordlist: $WORDLIST${NC}"
                break
            else
                echo -e "${RED}[!] Default wordlist not found at: $WORDLIST${NC}"
                echo -e "${YELLOW}[→] Please provide a valid path or Ctrl+C to cancel${NC}"
                continue
            fi
        elif [[ -f "$WORDLIST" ]]; then
            echo -e "${GREEN}[✓] Wordlist found: $WORDLIST${NC}"
            break
        else
            echo -e "${RED}[!] Wordlist not found at: $WORDLIST${NC}"
            echo -e "${YELLOW}[→] Please try again or Ctrl+C to cancel${NC}"
        fi
    done
else
    echo -e "${YELLOW}[→] Skipping bruteforce scanning${NC}"
fi

# Validate domain list file if provided
if [[ -n "$domain_list" && ! -f "$domain_list" ]]; then
    echo -e "${RED}[!] Domain list file not found: $domain_list${NC}"
    exit 1
fi

# Start scan
start_timer
mkdir -p "$output_dir" || { echo -e "${RED}[!] Failed to create output directory${NC}"; exit 1; }

if [[ -n "$domain" ]]; then
    scan_domain "$domain"
elif [[ -f "$domain_list" ]]; then
    echo -e "${GREEN}[+] Processing domain list: ${YELLOW}$domain_list${NC}"
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        [[ -z "$domain" ]] && continue
        scan_domain "$domain"
    done < "$domain_list"
fi

# Final report
total_elapsed=$(( $(date +%s) - scan_start_time ))
echo -e "\n${PURPLE}==============================================${NC}"
echo -e "${GREEN}[✓] Scan completed in $(printf "%02d:%02d:%02d" $((total_elapsed/3600)) $((total_elapsed%3600/60)) $((total_elapsed%60)))${NC}"
echo -e "${CYAN}[→] Results saved to: ${YELLOW}$output_dir${NC}"
echo -e "${PURPLE}==============================================${NC}"
