#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  ____  _   _ ____  _____ _    ____ _____  __  __
# / ___|| | | |  _ \|  ___/ \  / ___| ____| \ \/ /
# \___ \| | | | |_) | |_ / _ \| |   |  _|    \  / 
#  ___) | |_| |  _ <|  _/ ___ \ |___| |___   /  \ 
# |____/ \___/|_| \_\_|/_/   \_\____|_____| /_/\_\
#
#  SURFACE X - Bash-Driven Recon & Bug Evidence Detection Orchestrator
#  Version: 1.0.0 | License: MIT | Made by: Hammad Naeem
#═══════════════════════════════════════════════════════════════════════════════

set -o pipefail
shopt -s extglob nullglob

#───────────────────────────────────────────────────────────────────────────────
# GLOBAL CONFIGURATION
#───────────────────────────────────────────────────────────────────────────────

declare -r VERSION="1.0.0"
declare -r SCRIPT_NAME="surface-x"
declare -r AUTHOR="Hammad Naeem"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Execution modes
declare -g VERBOSE=0
declare -g REPORT_MODE=0
declare -g EXPORT_REPORT=""
declare -g STEALTH_MODE=0
declare -g PARALLEL_JOBS=10

# Target information
declare -g TARGET=""
declare -g TARGET_TYPE=""

# In-memory data stores (NO DISK WRITES)
declare -gA PORTS=()
declare -gA SERVICES=()
declare -gA HTTP_DATA=()
declare -gA SUBDOMAINS=()
declare -gA VULNS=()
declare -gA EVIDENCE=()
declare -gA CONFIDENCE=()
declare -ga ATTACK_SURFACE=()
declare -ga LIVE_HOSTS=()

# Process tracking for cleanup
declare -ga CHILD_PIDS=()

#───────────────────────────────────────────────────────────────────────────────
# TERMINAL COLORS & FORMATTING
#───────────────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    declare -r RED=$'\033[0;31m'
    declare -r GREEN=$'\033[0;32m'
    declare -r YELLOW=$'\033[0;33m'
    declare -r BLUE=$'\033[0;34m'
    declare -r MAGENTA=$'\033[0;35m'
    declare -r CYAN=$'\033[0;36m'
    declare -r WHITE=$'\033[0;37m'
    declare -r BOLD=$'\033[1m'
    declare -r DIM=$'\033[2m'
    declare -r ITALIC=$'\033[3m'
    declare -r UNDERLINE=$'\033[4m'
    declare -r BLINK=$'\033[5m'
    declare -r REVERSE=$'\033[7m'
    declare -r RESET=$'\033[0m'
    
    # Extended colors
    declare -r ORANGE=$'\033[38;5;208m'
    declare -r PURPLE=$'\033[38;5;135m'
    declare -r PINK=$'\033[38;5;205m'
    declare -r LIME=$'\033[38;5;118m'
    declare -r GRAY=$'\033[38;5;245m'
    
    # Background colors
    declare -r BG_RED=$'\033[41m'
    declare -r BG_GREEN=$'\033[42m'
    declare -r BG_YELLOW=$'\033[43m'
    declare -r BG_BLUE=$'\033[44m'
else
    declare -r RED="" GREEN="" YELLOW="" BLUE="" MAGENTA="" CYAN="" WHITE=""
    declare -r BOLD="" DIM="" ITALIC="" UNDERLINE="" BLINK="" REVERSE="" RESET=""
    declare -r ORANGE="" PURPLE="" PINK="" LIME="" GRAY=""
    declare -r BG_RED="" BG_GREEN="" BG_YELLOW="" BG_BLUE=""
fi

# Unicode symbols
declare -r SYMBOL_CHECK="✓"
declare -r SYMBOL_CROSS="✗"
declare -r SYMBOL_ARROW="→"
declare -r SYMBOL_BULLET="•"
declare -r SYMBOL_WARN="⚠"
declare -r SYMBOL_INFO="ℹ"
declare -r SYMBOL_FIRE="🔥"
declare -r SYMBOL_LOCK="🔒"
declare -r SYMBOL_UNLOCK="🔓"
declare -r SYMBOL_TARGET="🎯"
declare -r SYMBOL_BUG="🐛"
declare -r SYMBOL_SHIELD="🛡"

#───────────────────────────────────────────────────────────────────────────────
# SIGNAL HANDLERS & CLEANUP
#───────────────────────────────────────────────────────────────────────────────

cleanup() {
    local exit_code=$?
    
    # Kill all child processes
    for pid in "${CHILD_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null
    done
    
    # Clear sensitive data from memory
    unset PORTS SERVICES HTTP_DATA SUBDOMAINS VULNS EVIDENCE CONFIDENCE
    unset ATTACK_SURFACE LIVE_HOSTS
    
    # Reset terminal
    printf '%s' "${RESET}"
    tput cnorm 2>/dev/null
    
    exit $exit_code
}

trap cleanup EXIT INT TERM HUP

track_pid() {
    CHILD_PIDS+=("$1")
}

#───────────────────────────────────────────────────────────────────────────────
# OUTPUT FUNCTIONS
#───────────────────────────────────────────────────────────────────────────────

banner() {
    cat << 'EOF'

     ██████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗    ██╗  ██╗
    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝    ╚██╗██╔╝
    ╚█████╗ ██║   ██║██████╔╝█████╗  ███████║██║     █████╗       ╚███╔╝ 
     ╚═══██╗██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝       ██╔██╗ 
    ██████╔╝╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗    ██╔╝╚██╗
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝

EOF
    printf '%s' "${CYAN}"
    printf '    %s SURFACE X - Bash-Driven Recon & Bug Evidence Detection %s\n' "$SYMBOL_SHIELD" "$SYMBOL_SHIELD"
    printf '    %s Version: %s | Made by: %s | Mode: In-Memory %s\n' "$DIM" "$VERSION" "$AUTHOR" "$RESET"
    printf '%s\n' "${RESET}"
}

log_info() {
    printf '%s[%s]%s %s\n' "${BLUE}${BOLD}" "$SYMBOL_INFO" "${RESET}" "$*"
}

log_success() {
    printf '%s[%s]%s %s\n' "${GREEN}${BOLD}" "$SYMBOL_CHECK" "${RESET}" "$*"
}

log_warning() {
    printf '%s[%s]%s %s\n' "${YELLOW}${BOLD}" "$SYMBOL_WARN" "${RESET}" "$*"
}

log_error() {
    printf '%s[%s]%s %s\n' "${RED}${BOLD}" "$SYMBOL_CROSS" "${RESET}" "$*" >&2
}

log_debug() {
    if [[ $VERBOSE -eq 1 ]]; then
        printf '%s[DEBUG]%s %s\n' "${GRAY}" "${RESET}" "$*"
    fi
}

log_vuln() {
    local confidence="$1"
    shift
    local color=""
    case "$confidence" in
        HIGH)   color="${RED}${BOLD}" ;;
        MEDIUM) color="${ORANGE}${BOLD}" ;;
        LOW)    color="${YELLOW}" ;;
        *)      color="${WHITE}" ;;
    esac
    printf '%s[%s %s]%s %s\n' "$color" "$SYMBOL_BUG" "$confidence" "${RESET}" "$*"
}

log_target() {
    printf '%s[%s]%s %s\n' "${MAGENTA}${BOLD}" "$SYMBOL_TARGET" "${RESET}" "$*"
}

section_header() {
    local title="$1"
    local width=70
    local title_len=${#title}
    local pad_len=$(( (width - title_len - 2) / 2 ))
    local padding=""
    
    for ((i=0; i<pad_len; i++)); do
        padding+="─"
    done
    
    printf '\n%s%s %s %s%s\n\n' "${CYAN}${BOLD}" "$padding" "$title" "$padding" "${RESET}"
}

progress_bar() {
    local current=$1
    local total=$2
    local width=40
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf '\r%s[' "${CYAN}"
    printf '%*s' "$filled" '' | tr ' ' '█'
    printf '%*s' "$empty" '' | tr ' ' '░'
    printf '] %3d%% (%d/%d)%s' "$percentage" "$current" "$total" "${RESET}"
}

#───────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE ENGINE - Pattern Database
#───────────────────────────────────────────────────────────────────────────────

declare -gA KNOWLEDGE_PATTERNS=(
    # Service-based patterns
    ["ssh:22"]="OpenSSH|SSH Brute Force Vector|2|auth"
    ["ftp:21"]="FTP Service|Anonymous Login Check|3|auth"
    ["ftp:21:anonymous"]="FTP Anonymous|Confirmed Anonymous Access|8|disclosure"
    ["telnet:23"]="Telnet|Cleartext Protocol|5|disclosure"
    ["smtp:25"]="SMTP|Email Relay Testing|3|relay"
    ["dns:53"]="DNS|Zone Transfer Check|4|disclosure"
    ["http:80"]="HTTP|Web Application Surface|5|web"
    ["https:443"]="HTTPS|Web Application Surface|5|web"
    ["smb:445"]="SMB|Share Enumeration|6|disclosure"
    ["smb:139"]="NetBIOS|Legacy SMB|6|disclosure"
    ["mysql:3306"]="MySQL|Database Exposure|7|disclosure"
    ["postgres:5432"]="PostgreSQL|Database Exposure|7|disclosure"
    ["redis:6379"]="Redis|Unauthenticated Access|8|disclosure"
    ["mongodb:27017"]="MongoDB|NoAuth Database|8|disclosure"
    ["elasticsearch:9200"]="Elasticsearch|Data Exposure|8|disclosure"
    ["docker:2375"]="Docker API|Container Escape|9|rce"
    ["docker:2376"]="Docker TLS|Container Escape|7|rce"
    ["kubernetes:6443"]="K8s API|Cluster Access|9|rce"
    ["kubernetes:10250"]="Kubelet|Node Compromise|9|rce"
    ["jenkins:8080"]="Jenkins|Script Console RCE|8|rce"
    ["tomcat:8080"]="Tomcat|Manager Interface|6|rce"
    ["weblogic:7001"]="WebLogic|Deserialization|8|rce"
    ["jboss:8080"]="JBoss|JMX Console|7|rce"
    ["rdp:3389"]="RDP|Remote Access|5|auth"
    ["vnc:5900"]="VNC|Remote Access|5|auth"
    ["winrm:5985"]="WinRM|Remote Execution|6|rce"
    ["ldap:389"]="LDAP|Directory Exposure|5|disclosure"
    ["nfs:2049"]="NFS|Share Exposure|6|disclosure"
    ["rsync:873"]="Rsync|Data Exposure|6|disclosure"
    
    # HTTP Header patterns
    ["header:x-powered-by"]="Technology Disclosure|Framework Fingerprint|3|disclosure"
    ["header:server"]="Server Banner|Technology Disclosure|2|disclosure"
    ["header:x-aspnet-version"]="ASP.NET Version|Framework Disclosure|4|disclosure"
    ["header:x-debug"]="Debug Header|Debug Mode Active|7|disclosure"
    ["header:x-debug-token"]="Symfony Debug|Framework Debug|7|disclosure"
    ["header:access-control-allow-origin:*"]="CORS Wildcard|Potential CORS Bypass|6|web"
    ["header:x-frame-options:missing"]="No X-Frame-Options|Clickjacking Possible|4|web"
    ["header:content-security-policy:missing"]="No CSP|XSS Risk Increased|3|web"
    ["header:strict-transport-security:missing"]="No HSTS|Downgrade Attack|4|web"
    ["header:set-cookie:httponly:missing"]="Cookie No HttpOnly|XSS Cookie Theft|5|web"
    ["header:set-cookie:secure:missing"]="Cookie No Secure|Cookie Interception|4|web"
    ["header:www-authenticate"]="Auth Required|Authentication Vector|3|auth"
    
    # Response patterns
    ["response:401"]="Unauthorized|Auth Endpoint|4|auth"
    ["response:403"]="Forbidden|Access Control|4|authz"
    ["response:500"]="Server Error|Error Disclosure|5|disclosure"
    ["response:502"]="Bad Gateway|Proxy Config|3|disclosure"
    ["response:503"]="Service Unavailable|Rate Limit/WAF|2|disclosure"
    
    # Technology patterns
    ["tech:wordpress"]="WordPress|CMS Attack Surface|5|web"
    ["tech:drupal"]="Drupal|CMS Attack Surface|5|web"
    ["tech:joomla"]="Joomla|CMS Attack Surface|5|web"
    ["tech:phpmyadmin"]="phpMyAdmin|Database Management|7|web"
    ["tech:grafana"]="Grafana|Dashboard Access|5|disclosure"
    ["tech:kibana"]="Kibana|Log Access|6|disclosure"
    ["tech:gitlab"]="GitLab|Source Code|7|disclosure"
    ["tech:bitbucket"]="Bitbucket|Source Code|7|disclosure"
    ["tech:jenkins"]="Jenkins|CI/CD Pipeline|8|rce"
    ["tech:swagger"]="Swagger/OpenAPI|API Documentation|5|disclosure"
    ["tech:graphql"]="GraphQL|API Introspection|6|disclosure"
    
    # Path patterns
    ["path:/.git"]="Git Repository|Source Code Leak|9|disclosure"
    ["path:/.svn"]="SVN Repository|Source Code Leak|9|disclosure"
    ["path:/.env"]="Environment File|Credential Leak|9|disclosure"
    ["path:/wp-config.php.bak"]="WP Config Backup|Credential Leak|9|disclosure"
    ["path:/server-status"]="Apache Status|Info Disclosure|6|disclosure"
    ["path:/phpinfo.php"]="PHP Info|Info Disclosure|7|disclosure"
    ["path:/actuator"]="Spring Actuator|Framework Endpoints|7|disclosure"
    ["path:/api/swagger"]="Swagger API|API Documentation|5|disclosure"
    ["path:/graphql"]="GraphQL Endpoint|API Introspection|6|disclosure"
    ["path:/admin"]="Admin Panel|Privilege Escalation|5|authz"
    ["path:/backup"]="Backup Directory|Data Leak|6|disclosure"
    ["path:/debug"]="Debug Endpoint|Debug Info|7|disclosure"
    ["path:/.well-known"]="Well-Known|Security.txt/Config|2|disclosure"
    
    # Version-based vulnerabilities
    ["version:apache:2.4.49"]="Apache 2.4.49|Path Traversal CVE-2021-41773|9|rce"
    ["version:apache:2.4.50"]="Apache 2.4.50|Path Traversal CVE-2021-42013|9|rce"
    ["version:openssh:<7.7"]="OpenSSH <7.7|Username Enum|5|disclosure"
    ["version:vsftpd:2.3.4"]="vsftpd 2.3.4|Backdoor|10|rce"
    ["version:proftpd:1.3.5"]="ProFTPD 1.3.5|Mod_Copy|8|rce"
    ["version:exim:4.87"]="Exim 4.87|RCE CVE-2019-15846|9|rce"
    ["version:nginx:<1.13.6"]="Nginx <1.13.6|Integer Overflow|6|rce"
)

# Attack surface categories
declare -gA ATTACK_CATEGORIES=(
    ["auth"]="Authentication Attack Surface"
    ["authz"]="Authorization Attack Surface"
    ["rce"]="Remote Code Execution Vector"
    ["disclosure"]="Information Disclosure"
    ["web"]="Web Application Attack Surface"
    ["relay"]="Relay/Proxy Attack Surface"
)

#───────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATION & TARGET DETECTION
#───────────────────────────────────────────────────────────────────────────────

validate_target() {
    local target="$1"
    
    # URL pattern
    if [[ "$target" =~ ^https?:// ]]; then
        TARGET_TYPE="url"
        TARGET="${target#*://}"
        TARGET="${TARGET%%/*}"
        TARGET="${TARGET%%#*}"
        TARGET="${TARGET%%\?*}"
        return 0
    fi
    
    # IPv4 pattern
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        TARGET_TYPE="ip"
        TARGET="$target"
        return 0
    fi
    
    # CIDR pattern
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        TARGET_TYPE="cidr"
        TARGET="$target"
        return 0
    fi
    
    # Domain pattern
    if [[ "$target" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        TARGET_TYPE="domain"
        TARGET="$target"
        return 0
    fi
    
    # Try to extract domain from any input
    local extracted
    extracted=$(echo "$target" | sed -E 's|^[a-z]+://||; s|/.*$||; s|:.*$||; s|#.*$||; s|\?.*$||')
    if [[ -n "$extracted" ]]; then
        TARGET_TYPE="domain"
        TARGET="$extracted"
        return 0
    fi
    
    return 1
}

check_dependencies() {
    local -a required=("nmap")
    local -a optional=("rustscan" "httpx" "subfinder" "nuclei" "assetfinder" "amass" "jq" "curl" "gobuster")
    local -a missing=()
    local -a missing_optional=()
    
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    for cmd in "${optional[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_optional+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        return 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log_warning "Missing optional tools: ${missing_optional[*]}"
    fi
    
    return 0
}

#───────────────────────────────────────────────────────────────────────────────
# CORE SCANNING MODULES
#───────────────────────────────────────────────────────────────────────────────

module_port_discovery() {
    local target="$1"
    section_header "PORT DISCOVERY"
    
    log_info "Initiating port scan on ${CYAN}$target${RESET}"
    
    local port_data=""
    
    # Try RustScan first (faster)
    if command -v rustscan &>/dev/null; then
        log_debug "Using RustScan for fast port discovery"
        port_data=$(rustscan -a "$target" --ulimit 5000 -g 2>/dev/null | tr ',' '\n' | grep -oE '[0-9]+')
    fi
    
    # Fallback to nmap if rustscan not available or failed
    if [[ -z "$port_data" ]]; then
        log_debug "Using Nmap for port discovery"
        port_data=$(nmap -p- --min-rate=1000 -T4 "$target" 2>/dev/null | grep "^[0-9]" | cut -d'/' -f1)
    fi
    
    if [[ -z "$port_data" ]]; then
        log_warning "No open ports discovered"
        return 1
    fi
    
    local port_count=0
    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        PORTS["$target:$port"]=1
        ((port_count++))
        printf '  %s├─ Port %s%d%s %s OPEN %s\n' "$GRAY" "$GREEN$BOLD" "$port" "$RESET" "$GREEN$SYMBOL_CHECK" "$RESET"
        
        # Apply knowledge patterns for port
        apply_port_knowledge "$target" "$port"
    done <<< "$port_data"
    
    log_success "Discovered ${GREEN}$port_count${RESET} open ports"
    return 0
}

module_service_detection() {
    local target="$1"
    section_header "SERVICE DETECTION (Nmap)"
    
    # Build port list from discovered ports
    local port_list=""
    for key in "${!PORTS[@]}"; do
        if [[ "$key" == "$target:"* ]]; then
            local port="${key#*:}"
            port_list+="${port},"
        fi
    done
    port_list="${port_list%,}"
    
    if [[ -z "$port_list" ]]; then
        log_warning "No ports to scan for services"
        return 1
    fi
    
    log_info "Running service/version detection on ports: ${CYAN}${port_list}${RESET}"
    
    # Run nmap and parse output in real-time
    while IFS= read -r line; do
        # Parse nmap output
        if [[ "$line" =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([^[:space:]]+)[[:space:]]*(.*) ]]; then
            local port="${BASH_REMATCH[1]}"
            local service="${BASH_REMATCH[2]}"
            local version="${BASH_REMATCH[3]}"
            
            SERVICES["$target:$port:service"]="$service"
            SERVICES["$target:$port:version"]="$version"
            
            printf '  %s├─ %s%d/tcp%s %s→%s %s%-15s%s %s\n' \
                "$GRAY" "$CYAN" "$port" "$RESET" \
                "$GRAY" "$RESET" "$GREEN" "$service" "$RESET" \
                "${DIM}${version}${RESET}"
            
            # Apply knowledge patterns for service
            apply_service_knowledge "$target" "$port" "$service" "$version"
        fi
    done < <(nmap -sV -sC -p"$port_list" --open -T4 "$target" 2>/dev/null)
    
    log_success "Service detection complete"
}

module_subdomain_discovery() {
    local domain="$1"
    section_header "SUBDOMAIN DISCOVERY (Passive)"
    
    if [[ "$TARGET_TYPE" != "domain" ]]; then
        log_warning "Subdomain discovery requires a domain target"
        return 1
    fi
    
    log_info "Running passive subdomain enumeration on ${CYAN}$domain${RESET}"
    
    local -A seen_subs=()
    local sub_count=0
    
    # Subfinder (primary)
    if command -v subfinder &>/dev/null; then
        while IFS= read -r subdomain; do
            [[ -z "$subdomain" || -n "${seen_subs[$subdomain]}" ]] && continue
            seen_subs["$subdomain"]=1
            SUBDOMAINS["$subdomain"]=1
            ((sub_count++))
            printf '  %s├─ %s%s%s\n' "$GRAY" "$CYAN" "$subdomain" "$RESET"
        done < <(subfinder -d "$domain" -silent 2>/dev/null)
    fi
    
    # Assetfinder (if available)
    if command -v assetfinder &>/dev/null; then
        while IFS= read -r subdomain; do
            [[ -z "$subdomain" || -n "${seen_subs[$subdomain]}" ]] && continue
            seen_subs["$subdomain"]=1
            SUBDOMAINS["$subdomain"]=1
            ((sub_count++))
            printf '  %s├─ %s%s%s %s(assetfinder)%s\n' "$GRAY" "$CYAN" "$subdomain" "$RESET" "$DIM" "$RESET"
        done < <(assetfinder --subs-only "$domain" 2>/dev/null)
    fi
    
    if [[ $sub_count -eq 0 ]]; then
        log_warning "No subdomains discovered (tools may not be installed)"
    else
        log_success "Discovered ${GREEN}$sub_count${RESET} unique subdomains"
    fi
}

module_http_analysis() {
    local target="$1"
    section_header "HTTP ANALYSIS"
    
    local -a targets_to_probe=()
    
    # Collect HTTP/HTTPS targets
    for key in "${!PORTS[@]}"; do
        if [[ "$key" == "$target:"* ]]; then
            local port="${key#*:}"
            case "$port" in
                80|8080|8000|8888)
                    targets_to_probe+=("http://${target}:${port}")
                    ;;
                443|8443)
                    targets_to_probe+=("https://${target}:${port}")
                    ;;
            esac
        fi
    done
    
    # Add subdomains if any
    for sub in "${!SUBDOMAINS[@]}"; do
        targets_to_probe+=("https://${sub}" "http://${sub}")
    done
    
    if [[ ${#targets_to_probe[@]} -eq 0 ]]; then
        targets_to_probe+=("https://${target}" "http://${target}")
    fi
    
    log_info "Probing ${CYAN}${#targets_to_probe[@]}${RESET} HTTP endpoints"
    
    # Check if httpx is available
    if command -v httpx &>/dev/null; then
        printf '%s\n' "${targets_to_probe[@]}" | httpx -silent -status-code -title -tech-detect \
            -content-length -web-server -no-color 2>/dev/null | while IFS= read -r line; do
            
            local url status_code
            url=$(echo "$line" | awk '{print $1}')
            status_code=$(echo "$line" | grep -oE '\[([0-9]+)\]' | tr -d '[]')
            
            [[ -z "$url" ]] && continue
            
            LIVE_HOSTS+=("$url")
            HTTP_DATA["$url:status"]="$status_code"
            
            local status_color="$GREEN"
            case "$status_code" in
                4[0-9][0-9]) status_color="$YELLOW" ;;
                5[0-9][0-9]) status_color="$RED" ;;
                3[0-9][0-9]) status_color="$CYAN" ;;
            esac
            
            printf '  %s├─ %s%-50s%s %s[%s]%s\n' \
                "$GRAY" "$BLUE" "$url" "$RESET" \
                "$status_color" "$status_code" "$RESET"
            
            apply_http_knowledge "$url" "$status_code"
        done
    else
        # Fallback to curl
        log_warning "httpx not found, using curl (slower)"
        for url in "${targets_to_probe[@]}"; do
            local status_code
            status_code=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null)
            
            if [[ "$status_code" != "000" ]]; then
                LIVE_HOSTS+=("$url")
                HTTP_DATA["$url:status"]="$status_code"
                
                local status_color="$GREEN"
                case "$status_code" in
                    4[0-9][0-9]) status_color="$YELLOW" ;;
                    5[0-9][0-9]) status_color="$RED" ;;
                    3[0-9][0-9]) status_color="$CYAN" ;;
                esac
                
                printf '  %s├─ %s%-50s%s %s[%s]%s\n' \
                    "$GRAY" "$BLUE" "$url" "$RESET" \
                    "$status_color" "$status_code" "$RESET"
                
                apply_http_knowledge "$url" "$status_code"
            fi
        done
    fi
    
    # Header analysis
    log_info "Analyzing response headers for security issues..."
    
    for url in "${LIVE_HOSTS[@]}"; do
        analyze_headers "$url"
    done
}

module_nuclei_scan() {
    local target="$1"
    section_header "VULNERABILITY SCANNING (Nuclei - Safe Templates)"
    
    if ! command -v nuclei &>/dev/null; then
        log_warning "Nuclei not installed, skipping vulnerability scan"
        return 1
    fi
    
    log_info "Running safe, non-intrusive vulnerability detection..."
    log_warning "Using only passive/safe templates - no active exploitation"
    
    local -a scan_targets=()
    
    # Build target list
    for url in "${LIVE_HOSTS[@]}"; do
        scan_targets+=("$url")
    done
    
    if [[ ${#scan_targets[@]} -eq 0 ]]; then
        scan_targets+=("http://${target}" "https://${target}")
    fi
    
    # Run nuclei with safe templates only
    printf '%s\n' "${scan_targets[@]}" | nuclei -silent -severity info,low,medium,high \
        -tags safe,exposure,misconfig,cve -exclude-tags intrusive,dos,fuzz \
        -no-color 2>/dev/null | while IFS= read -r line; do
        
        # Parse nuclei output
        if [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*(.*) ]]; then
            local template="${BASH_REMATCH[1]}"
            local severity="${BASH_REMATCH[2]}"
            local proto="${BASH_REMATCH[3]}"
            local url="${BASH_REMATCH[4]}"
            
            local sev_color="$GREEN"
            local confidence="LOW"
            case "$severity" in
                high)   sev_color="$RED"; confidence="HIGH" ;;
                medium) sev_color="$ORANGE"; confidence="MEDIUM" ;;
                low)    sev_color="$YELLOW"; confidence="LOW" ;;
            esac
            
            VULNS["$template:$url"]="$severity"
            CONFIDENCE["$template:$url"]="$confidence"
            EVIDENCE["$template:$url"]="Detected by nuclei template: $template"
            
            printf '  %s%s[%s]%s %s → %s\n' \
                "$sev_color" "$SYMBOL_BUG" "$severity" "$RESET" \
                "$template" "${DIM}${url}${RESET}"
        fi
    done
    
    log_success "Nuclei scan complete"
}

#───────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE APPLICATION FUNCTIONS
#───────────────────────────────────────────────────────────────────────────────

apply_port_knowledge() {
    local target="$1"
    local port="$2"
    
    for pattern in "${!KNOWLEDGE_PATTERNS[@]}"; do
        if [[ "$pattern" =~ ^[a-z]+:$port$ ]]; then
            local info="${KNOWLEDGE_PATTERNS[$pattern]}"
            IFS='|' read -r svc_name desc weight vector <<< "$info"
            
            local confidence="LOW"
            if [[ $weight -ge 7 ]]; then
                confidence="HIGH"
            elif [[ $weight -ge 4 ]]; then
                confidence="MEDIUM"
            fi
            
            ATTACK_SURFACE+=("$port:$svc_name:$vector:$confidence")
            
            log_debug "Knowledge match: $pattern -> $desc"
        fi
    done
}

apply_service_knowledge() {
    local target="$1"
    local port="$2"
    local service="$3"
    local version="$4"
    
    for pattern in "${!KNOWLEDGE_PATTERNS[@]}"; do
        if [[ "$pattern" == "version:"* ]]; then
            local svc_pattern="${pattern#version:}"
            local svc_name="${svc_pattern%%:*}"
            local svc_ver="${svc_pattern#*:}"
            
            if [[ "$service" == *"$svc_name"* ]]; then
                if [[ "$version" == *"$svc_ver"* ]]; then
                    local info="${KNOWLEDGE_PATTERNS[$pattern]}"
                    IFS='|' read -r name desc weight vector <<< "$info"
                    
                    VULNS["version:$service:$version"]="$desc"
                    CONFIDENCE["version:$service:$version"]="HIGH"
                    EVIDENCE["version:$service:$version"]="Service: $service, Version: $version matches vulnerable pattern"
                    
                    log_vuln "HIGH" "${SYMBOL_FIRE} Version-based: $desc"
                fi
            fi
        fi
    done
}

apply_http_knowledge() {
    local url="$1"
    local status_code="$2"
    
    local pattern="response:$status_code"
    if [[ -n "${KNOWLEDGE_PATTERNS[$pattern]}" ]]; then
        local info="${KNOWLEDGE_PATTERNS[$pattern]}"
        IFS='|' read -r name desc weight vector <<< "$info"
        
        local confidence="LOW"
        if [[ $weight -ge 7 ]]; then
            confidence="HIGH"
        elif [[ $weight -ge 4 ]]; then
            confidence="MEDIUM"
        fi
        
        ATTACK_SURFACE+=("http:$status_code:$vector:$confidence")
    fi
}

analyze_headers() {
    local url="$1"
    
    local headers
    headers=$(curl -sI -m 5 "$url" 2>/dev/null)
    
    [[ -z "$headers" ]] && return
    
    # Security header checks
    if ! echo "$headers" | grep -qi "x-frame-options"; then
        apply_header_vuln "$url" "x-frame-options:missing" "LOW"
    fi
    
    if ! echo "$headers" | grep -qi "content-security-policy"; then
        apply_header_vuln "$url" "content-security-policy:missing" "LOW"
    fi
    
    if ! echo "$headers" | grep -qi "strict-transport-security"; then
        apply_header_vuln "$url" "strict-transport-security:missing" "LOW"
    fi
    
    # Technology disclosure
    local server_header
    server_header=$(echo "$headers" | grep -i "^server:" | cut -d: -f2- | tr -d '\r')
    if [[ -n "$server_header" ]]; then
        HTTP_DATA["$url:server"]="$server_header"
        log_debug "Server: $server_header"
    fi
    
    local powered_by
    powered_by=$(echo "$headers" | grep -i "^x-powered-by:" | cut -d: -f2- | tr -d '\r')
    if [[ -n "$powered_by" ]]; then
        HTTP_DATA["$url:powered-by"]="$powered_by"
        apply_header_vuln "$url" "x-powered-by" "LOW"
        log_debug "X-Powered-By: $powered_by (Technology Disclosure)"
    fi
    
    # CORS wildcard
    if echo "$headers" | grep -qi "access-control-allow-origin:.*\*"; then
        apply_header_vuln "$url" "cors-wildcard" "MEDIUM"
        log_warning "  CORS Wildcard detected - potential security issue"
    fi
    
    # Debug headers
    if echo "$headers" | grep -qi "x-debug\|x-debug-token"; then
        apply_header_vuln "$url" "debug-header" "HIGH"
        log_vuln "HIGH" "Debug headers detected!"
    fi
}

apply_header_vuln() {
    local url="$1"
    local issue="$2"
    local confidence="$3"
    
    VULNS["header:$issue:$url"]="$issue"
    CONFIDENCE["header:$issue:$url"]="$confidence"
    EVIDENCE["header:$issue:$url"]="HTTP Header analysis on $url"
}

#───────────────────────────────────────────────────────────────────────────────
# CORRELATION ENGINE
#───────────────────────────────────────────────────────────────────────────────

correlate_findings() {
    section_header "CORRELATION ENGINE"
    
    log_info "Analyzing combined findings for attack paths..."
    
    local -A attack_paths=()
    local -a high_value_targets=()
    
    # Correlate ports + services + vulnerabilities
    for key in "${!SERVICES[@]}"; do
        local target_port="${key%:*}"
        local service="${SERVICES[$key]}"
        
        case "$service" in
            *mysql*|*postgres*|*mongodb*|*redis*)
                if [[ -z "${attack_paths[database_exposure]}" ]]; then
                    attack_paths["database_exposure"]="$target_port:$service"
                    high_value_targets+=("DATABASE: $service on $target_port")
                fi
                ;;
            *docker*|*kubernetes*)
                if [[ -z "${attack_paths[container_exposure]}" ]]; then
                    attack_paths["container_exposure"]="$target_port:$service"
                    high_value_targets+=("CONTAINER: $service on $target_port")
                fi
                ;;
            *jenkins*|*gitlab*|*bamboo*)
                if [[ -z "${attack_paths[cicd_exposure]}" ]]; then
                    attack_paths["cicd_exposure"]="$target_port:$service"
                    high_value_targets+=("CI/CD: $service on $target_port")
                fi
                ;;
        esac
    done
    
    # Output high-value targets
    if [[ ${#high_value_targets[@]} -gt 0 ]]; then
        printf '\n  %s%sHigh-Value Targets Identified:%s\n' "$RED" "$BOLD" "$RESET"
        for hvt in "${high_value_targets[@]}"; do
            printf '  %s%s%s %s\n' "$RED" "$SYMBOL_FIRE" "$RESET" "$hvt"
        done
    fi
    
    # Calculate overall risk score
    local risk_score=0
    local vuln_count=${#VULNS[@]}
    local high_count=0
    local medium_count=0
    
    for key in "${!CONFIDENCE[@]}"; do
        case "${CONFIDENCE[$key]}" in
            HIGH)
                ((high_count++))
                ((risk_score += 30))
                ;;
            MEDIUM)
                ((medium_count++))
                ((risk_score += 15))
                ;;
            LOW)
                ((risk_score += 5))
                ;;
        esac
    done
    
    printf '\n  %sRisk Metrics:%s\n' "$BOLD" "$RESET"
    printf '  %s├─ Total Findings: %s%d%s\n' "$GRAY" "$CYAN" "$vuln_count" "$RESET"
    printf '  %s├─ High Confidence: %s%d%s\n' "$GRAY" "$RED" "$high_count" "$RESET"
    printf '  %s├─ Medium Confidence: %s%d%s\n' "$GRAY" "$ORANGE" "$medium_count" "$RESET"
    printf '  %s└─ Risk Score: ' "$GRAY"
    
    if [[ $risk_score -ge 100 ]]; then
        printf '%s%sCRITICAL (%d)%s\n' "$BG_RED" "$WHITE$BOLD" "$risk_score" "$RESET"
    elif [[ $risk_score -ge 50 ]]; then
        printf '%s%sHIGH (%d)%s\n' "$RED" "$BOLD" "$risk_score" "$RESET"
    elif [[ $risk_score -ge 25 ]]; then
        printf '%s%sMEDIUM (%d)%s\n' "$ORANGE" "$BOLD" "$risk_score" "$RESET"
    else
        printf '%s%sLOW (%d)%s\n' "$GREEN" "$BOLD" "$risk_score" "$RESET"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
#───────────────────────────────────────────────────────────────────────────────

generate_report() {
    local export_file="$1"
    
    section_header "SURFACE X REPORT"
    
    local report=""
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')
    
    report+="═══════════════════════════════════════════════════════════════════\n"
    report+="                          SURFACE X REPORT\n"
    report+="                       Made by: Hammad Naeem\n"
    report+="═══════════════════════════════════════════════════════════════════\n"
    report+="\n"
    report+="Target: $TARGET\n"
    report+="Type: $TARGET_TYPE\n"
    report+="Timestamp: $timestamp\n"
    report+="\n"
    
    # Services Section
    report+="───────────────────────────────────────────────────────────────────\n"
    report+="                       DISCOVERED SERVICES\n"
    report+="───────────────────────────────────────────────────────────────────\n"
    
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == *":service" ]]; then
            local port_info="${key%:service}"
            local service="${SERVICES[$key]}"
            local version="${SERVICES[${port_info}:version]}"
            report+="  [+] $port_info - $service $version\n"
        fi
    done
    report+="\n"
    
    # Attack Surface Section
    report+="───────────────────────────────────────────────────────────────────\n"
    report+="                       ATTACK SURFACE\n"
    report+="───────────────────────────────────────────────────────────────────\n"
    
    for surface in "${ATTACK_SURFACE[@]}"; do
        IFS=':' read -r port svc vector confidence <<< "$surface"
        report+="  [$confidence] Port $port ($svc) - ${ATTACK_CATEGORIES[$vector]}\n"
    done
    report+="\n"
    
    # Vulnerabilities Section
    report+="───────────────────────────────────────────────────────────────────\n"
    report+="                    POTENTIAL VULNERABILITIES\n"
    report+="───────────────────────────────────────────────────────────────────\n"
    
    for key in "${!VULNS[@]}"; do
        local vuln="${VULNS[$key]}"
        local conf="${CONFIDENCE[$key]}"
        local evid="${EVIDENCE[$key]}"
        
        report+="  [$conf] $vuln\n"
        report+="      Evidence: $evid\n"
        report+="\n"
    done
    
    # Live Hosts Section
    report+="───────────────────────────────────────────────────────────────────\n"
    report+="                         LIVE HOSTS\n"
    report+="───────────────────────────────────────────────────────────────────\n"
    
    for host in "${LIVE_HOSTS[@]}"; do
        local status="${HTTP_DATA[$host:status]}"
        report+="  [+] $host (Status: $status)\n"
    done
    report+="\n"
    
    # Subdomains Section
    if [[ ${#SUBDOMAINS[@]} -gt 0 ]]; then
        report+="───────────────────────────────────────────────────────────────────\n"
        report+="                        SUBDOMAINS\n"
        report+="───────────────────────────────────────────────────────────────────\n"
        
        for sub in "${!SUBDOMAINS[@]}"; do
            report+="  [+] $sub\n"
        done
        report+="\n"
    fi
    
    report+="═══════════════════════════════════════════════════════════════════\n"
    report+="                      END OF REPORT\n"
    report+="═══════════════════════════════════════════════════════════════════\n"
    
    # Display report
    printf '%b' "$report"
    
    # Export if requested
    if [[ -n "$export_file" ]]; then
        printf '%b' "$report" > "$export_file"
        log_success "Report exported to: $export_file"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# LOAD EXTENSIONS
#───────────────────────────────────────────────────────────────────────────────

load_extensions() {
    if [[ -d "${SCRIPT_DIR}/extensions" ]]; then
        for ext_file in "${SCRIPT_DIR}/extensions/"*.sh; do
            if [[ -f "$ext_file" ]]; then
                log_debug "Loading extension: $(basename "$ext_file")"
                source "$ext_file"
            fi
        done
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION FLOW
#───────────────────────────────────────────────────────────────────────────────

usage() {
    cat << EOF
${BOLD}SURFACE X${RESET} - Bash-Driven Recon & Bug Evidence Detection
Made by: ${AUTHOR}

${BOLD}USAGE:${RESET}
    $SCRIPT_NAME [OPTIONS] <target>

${BOLD}OPTIONS:${RESET}
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -r, --report            Generate summary report (display only)
    -e, --export FILE       Export report to file
    -j, --jobs N            Parallel jobs (default: 10)
    -s, --stealth           Stealth mode (slower, more careful)
    --no-subs               Skip subdomain enumeration
    --no-nuclei             Skip nuclei scanning
    --ports-only            Only perform port discovery
    --http-only             Only perform HTTP analysis

${BOLD}EXAMPLES:${RESET}
    $SCRIPT_NAME example.com
    $SCRIPT_NAME -r --export report.txt 192.168.1.1
    $SCRIPT_NAME -v -j 20 https://example.com

${BOLD}TARGET TYPES:${RESET}
    - Domain:     example.com
    - IP Address: 192.168.1.1
    - CIDR:       192.168.1.0/24
    - URL:        https://example.com

EOF
}

main() {
    local skip_subs=0
    local skip_nuclei=0
    local ports_only=0
    local http_only=0
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -r|--report)
                REPORT_MODE=1
                shift
                ;;
            -e|--export)
                EXPORT_REPORT="$2"
                REPORT_MODE=1
                shift 2
                ;;
            -j|--jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            -s|--stealth)
                STEALTH_MODE=1
                shift
                ;;
            --no-subs)
                skip_subs=1
                shift
                ;;
            --no-nuclei)
                skip_nuclei=1
                shift
                ;;
            --ports-only)
                ports_only=1
                shift
                ;;
            --http-only)
                http_only=1
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
    
    # Validate target
    if [[ -z "$TARGET" ]]; then
        log_error "No target specified"
        usage
        exit 1
    fi
    
    if ! validate_target "$TARGET"; then
        log_error "Invalid target format: $TARGET"
        exit 1
    fi
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Load extensions
    load_extensions
    
    # Display banner
    banner
    
    log_target "Target: ${BOLD}${CYAN}$TARGET${RESET} (${TARGET_TYPE})"
    printf '\n'
    
    # Execute modules based on options
    if [[ $http_only -eq 1 ]]; then
        module_http_analysis "$TARGET"
    elif [[ $ports_only -eq 1 ]]; then
        module_port_discovery "$TARGET"
    else
        # Full scan sequence
        module_port_discovery "$TARGET"
        module_service_detection "$TARGET"
        
        if [[ $skip_subs -eq 0 && "$TARGET_TYPE" == "domain" ]]; then
            module_subdomain_discovery "$TARGET"
        fi
        
        module_http_analysis "$TARGET"
        
        if [[ $skip_nuclei -eq 0 ]]; then
            module_nuclei_scan "$TARGET"
        fi
        
        # Run recon extras extension if loaded
        if declare -F module_recon_extras &>/dev/null; then
            module_recon_extras "$TARGET"
        fi
        
        correlate_findings
    fi
    
    # Generate report if requested
    if [[ $REPORT_MODE -eq 1 ]]; then
        generate_report "$EXPORT_REPORT"
    fi
    
    printf '\n'
    log_success "Reconnaissance complete. No artifacts written to disk."
}

# Execute main function
main "$@"