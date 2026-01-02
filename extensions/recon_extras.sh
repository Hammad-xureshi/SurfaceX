#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SURFACE X - Extension Module: Recon Extras
#  Author: Hammad Naeem
#  
#  Features:
#    • Gobuster Directory Enumeration
#    • SSH Support Detection + Banner Grabbing
#    • FTP Support Detection + Anonymous Login Check
#═══════════════════════════════════════════════════════════════════════════════

#───────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
#───────────────────────────────────────────────────────────────────────────────

# Default wordlist for gobuster (change if needed)
declare -g GOBUSTER_WORDLIST="${GOBUSTER_WORDLIST:-/usr/share/wordlists/dirb/common.txt}"

# Alternative wordlists to try if default not found
declare -ga WORDLIST_ALTERNATIVES=(
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/wordlists/wfuzz/general/common.txt"
)

# Gobuster threads
declare -g GOBUSTER_THREADS=50

# Timeout for network checks (seconds)
declare -g NET_TIMEOUT=5

#───────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
#───────────────────────────────────────────────────────────────────────────────

# Find available netcat binary
_get_netcat() {
    local nc_bin=""
    for cmd in nc ncat netcat; do
        command -v "$cmd" &>/dev/null && { nc_bin="$cmd"; break; }
    done
    echo "$nc_bin"
}

# Find available wordlist
_find_wordlist() {
    # Check custom wordlist first
    [[ -f "$GOBUSTER_WORDLIST" ]] && { echo "$GOBUSTER_WORDLIST"; return 0; }
    
    # Try alternatives
    for wl in "${WORDLIST_ALTERNATIVES[@]}"; do
        [[ -f "$wl" ]] && { echo "$wl"; return 0; }
    done
    
    return 1
}

# Check if port is open (quick check)
_is_port_open() {
    local host="$1"
    local port="$2"
    timeout "$NET_TIMEOUT" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
}

# Extract host from URL
_url_to_host() {
    local url="$1"
    echo "$url" | sed -E 's|^https?://||; s|/.*$||; s|:.*$||'
}

#───────────────────────────────────────────────────────────────────────────────
# MODULE: GOBUSTER DIRECTORY ENUMERATION
#───────────────────────────────────────────────────────────────────────────────

module_gobuster_enum() {
    local url="$1"
    
    section_header "DIRECTORY ENUMERATION (Gobuster)"
    
    # Check if gobuster exists
    if ! command -v gobuster &>/dev/null; then
        log_error "Gobuster not installed!"
        log_info "Install: ${CYAN}sudo apt install gobuster${RESET}"
        log_info "   or:   ${CYAN}go install github.com/OJ/gobuster/v3@latest${RESET}"
        return 1
    fi
    
    # Find wordlist
    local wordlist
    wordlist=$(_find_wordlist)
    
    if [[ -z "$wordlist" ]]; then
        log_error "No wordlist found!"
        log_info "Install: ${CYAN}sudo apt install wordlists seclists${RESET}"
        log_info "Or set custom: ${CYAN}export GOBUSTER_WORDLIST=/path/to/wordlist.txt${RESET}"
        return 1
    fi
    
    log_info "Target: ${CYAN}$url${RESET}"
    log_info "Wordlist: ${DIM}$wordlist${RESET}"
    log_info "Threads: ${DIM}$GOBUSTER_THREADS${RESET}"
    printf '\n'
    
    # Counter for findings
    local found_count=0
    local interesting_count=0
    
    # Run gobuster and parse output
    gobuster dir -u "$url" -w "$wordlist" -q -t "$GOBUSTER_THREADS" \
        --no-error --no-color -z 2>/dev/null | while IFS= read -r line; do
        
        [[ -z "$line" ]] && continue
        
        # Parse gobuster output
        # Format: /path (Status: 200) [Size: 1234]
        local path status size
        
        if [[ "$line" =~ ^(/[^[:space:]]*)[[:space:]]+\(Status:[[:space:]]+([0-9]+)\)[[:space:]]+\[Size:[[:space:]]+([0-9]+)\] ]]; then
            path="${BASH_REMATCH[1]}"
            status="${BASH_REMATCH[2]}"
            size="${BASH_REMATCH[3]}"
        else
            # Alternative parsing
            path=$(echo "$line" | awk '{print $1}')
            status=$(echo "$line" | grep -oE 'Status: [0-9]+' | awk '{print $2}')
            size=$(echo "$line" | grep -oE 'Size: [0-9]+' | awk '{print $2}')
        fi
        
        [[ -z "$path" ]] && continue
        ((found_count++))
        
        # Color based on status code
        local status_color="$GREEN"
        local status_icon="$SYMBOL_CHECK"
        case "$status" in
            200)        status_color="$GREEN"; status_icon="$SYMBOL_CHECK" ;;
            301|302)    status_color="$CYAN"; status_icon="$SYMBOL_ARROW" ;;
            401|403)    status_color="$YELLOW"; status_icon="$SYMBOL_LOCK" ;;
            404)        continue ;;  # Skip 404s
            500|502|503) status_color="$RED"; status_icon="$SYMBOL_WARN" ;;
            *)          status_color="$WHITE" ;;
        esac
        
        # Print finding
        printf '  %s├─ %s%-35s%s %s[%s]%s %sSize: %s%s\n' \
            "$GRAY" "$BLUE" "$path" "$RESET" \
            "$status_color" "$status" "$RESET" \
            "$DIM" "$size" "$RESET"
        
        # Check against knowledge patterns
        local pattern_key="path:$path"
        if [[ -n "${KNOWLEDGE_PATTERNS[$pattern_key]}" ]]; then
            IFS='|' read -r name desc weight vector <<< "${KNOWLEDGE_PATTERNS[$pattern_key]}"
            
            local confidence="LOW"
            ((weight >= 7)) && confidence="HIGH"
            ((weight >= 4 && weight < 7)) && confidence="MEDIUM"
            
            VULNS["gobuster:$url$path"]="$desc"
            CONFIDENCE["gobuster:$url$path"]="$confidence"
            EVIDENCE["gobuster:$url$path"]="Found at ${url}${path} (HTTP $status, Size: $size bytes)"
            
            ((interesting_count++))
            log_vuln "$confidence" "${SYMBOL_FIRE} $desc"
        fi
        
        # Check for interesting paths (even if not in knowledge base)
        case "$path" in
            *admin*|*login*|*dashboard*|*panel*|*manage*)
                if [[ -z "${VULNS[gobuster:$url$path]}" ]]; then
                    VULNS["gobuster:$url$path"]="Admin/Login Interface"
                    CONFIDENCE["gobuster:$url$path"]="MEDIUM"
                    EVIDENCE["gobuster:$url$path"]="Potential admin interface at ${url}${path}"
                    ((interesting_count++))
                    log_vuln "MEDIUM" "Potential admin interface: $path"
                fi
                ;;
            *backup*|*bak*|*old*|*copy*|*.bak|*.old)
                if [[ -z "${VULNS[gobuster:$url$path]}" ]]; then
                    VULNS["gobuster:$url$path"]="Backup File/Directory"
                    CONFIDENCE["gobuster:$url$path"]="MEDIUM"
                    EVIDENCE["gobuster:$url$path"]="Potential backup at ${url}${path}"
                    ((interesting_count++))
                    log_vuln "MEDIUM" "Potential backup: $path"
                fi
                ;;
            *upload*|*file*|*files*|*uploads*)
                if [[ -z "${VULNS[gobuster:$url$path]}" ]]; then
                    VULNS["gobuster:$url$path"]="Upload Directory"
                    CONFIDENCE["gobuster:$url$path"]="LOW"
                    EVIDENCE["gobuster:$url$path"]="Upload directory at ${url}${path}"
                    ((interesting_count++))
                    log_vuln "LOW" "Upload directory: $path"
                fi
                ;;
            *api*|*v1*|*v2*|*rest*|*graphql*)
                if [[ -z "${VULNS[gobuster:$url$path]}" ]]; then
                    VULNS["gobuster:$url$path"]="API Endpoint"
                    CONFIDENCE["gobuster:$url$path"]="LOW"
                    EVIDENCE["gobuster:$url$path"]="API endpoint at ${url}${path}"
                    ((interesting_count++))
                    log_vuln "LOW" "API endpoint: $path"
                fi
                ;;
            *config*|*conf*|*settings*|*setup*)
                if [[ -z "${VULNS[gobuster:$url$path]}" ]]; then
                    VULNS["gobuster:$url$path"]="Configuration Path"
                    CONFIDENCE["gobuster:$url$path"]="MEDIUM"
                    EVIDENCE["gobuster:$url$path"]="Configuration path at ${url}${path}"
                    ((interesting_count++))
                    log_vuln "MEDIUM" "Configuration path: $path"
                fi
                ;;
        esac
        
    done
    
    printf '\n'
    log_success "Gobuster scan complete"
    log_info "Directories found: ${GREEN}$found_count${RESET}"
    log_info "Interesting findings: ${YELLOW}$interesting_count${RESET}"
}

#───────────────────────────────────────────────────────────────────────────────
# MODULE: SSH SUPPORT CHECK
#───────────────────────────────────────────────────────────────────────────────

module_ssh_check() {
    local host="$1"
    local port="${2:-22}"
    
    section_header "SSH SUPPORT CHECK"
    
    log_info "Checking SSH on ${CYAN}$host:$port${RESET}"
    
    # Check if port is open
    if ! _is_port_open "$host" "$port"; then
        printf '  %s└─ %sSSH port %d is CLOSED%s\n' "$GRAY" "$RED" "$port" "$RESET"
        log_warning "SSH not available on $host:$port"
        return 1
    fi
    
    printf '  %s├─ %sSSH port %d is OPEN%s %s\n' \
        "$GRAY" "$GREEN" "$port" "$RESET" "$SYMBOL_CHECK"
    
    # Grab SSH banner
    local nc_bin
    nc_bin=$(_get_netcat)
    
    local banner=""
    local ssh_version=""
    
    if [[ -n "$nc_bin" ]]; then
        banner=$(timeout "$NET_TIMEOUT" "$nc_bin" -nv "$host" "$port" 2>&1 | head -n1)
        
        if [[ -n "$banner" ]]; then
            printf '  %s├─ Banner: %s%s%s\n' "$GRAY" "$CYAN" "$banner" "$RESET"
            
            # Extract SSH version
            if [[ "$banner" =~ SSH-[0-9.]+-([^[:space:]]+) ]]; then
                ssh_version="${BASH_REMATCH[1]}"
                printf '  %s├─ SSH Software: %s%s%s\n' "$GRAY" "$GREEN" "$ssh_version" "$RESET"
            fi
            
            # Check for known vulnerable versions
            if [[ "$banner" == *"OpenSSH_7.2"* ]] || [[ "$banner" == *"OpenSSH_7.1"* ]] || \
               [[ "$banner" == *"OpenSSH_6."* ]] || [[ "$banner" == *"OpenSSH_5."* ]]; then
                log_vuln "MEDIUM" "Potentially outdated OpenSSH version detected"
                VULNS["ssh-version:$host:$port"]="Outdated SSH Version"
                CONFIDENCE["ssh-version:$host:$port"]="MEDIUM"
                EVIDENCE["ssh-version:$host:$port"]="SSH Banner: $banner"
            fi
            
            # Check for dropbear (often on embedded devices)
            if [[ "$banner" == *"dropbear"* ]]; then
                log_info "  ${DIM}Dropbear SSH detected (likely embedded device)${RESET}"
                VULNS["ssh-dropbear:$host:$port"]="Dropbear SSH (Embedded Device)"
                CONFIDENCE["ssh-dropbear:$host:$port"]="LOW"
                EVIDENCE["ssh-dropbear:$host:$port"]="SSH Banner: $banner"
            fi
        fi
    else
        log_warning "No netcat available - cannot grab SSH banner"
    fi
    
    # Add to attack surface
    ATTACK_SURFACE+=("$port:SSH:auth:MEDIUM")
    
    printf '  %s└─ %sSSH login surface available%s %s\n' \
        "$GRAY" "$GREEN" "$RESET" "$SYMBOL_UNLOCK"
    
    log_success "SSH check complete for $host:$port"
    
    # Store result
    SERVICES["$host:$port:ssh_supported"]="yes"
    [[ -n "$banner" ]] && SERVICES["$host:$port:ssh_banner"]="$banner"
    
    return 0
}

#───────────────────────────────────────────────────────────────────────────────
# MODULE: FTP SUPPORT CHECK + ANONYMOUS LOGIN
#───────────────────────────────────────────────────────────────────────────────

module_ftp_check() {
    local host="$1"
    local port="${2:-21}"
    
    section_header "FTP SUPPORT CHECK"
    
    log_info "Checking FTP on ${CYAN}$host:$port${RESET}"
    
    # Check if port is open
    if ! _is_port_open "$host" "$port"; then
        printf '  %s└─ %sFTP port %d is CLOSED%s\n' "$GRAY" "$RED" "$port" "$RESET"
        log_warning "FTP not available on $host:$port"
        return 1
    fi
    
    printf '  %s├─ %sFTP port %d is OPEN%s %s\n' \
        "$GRAY" "$GREEN" "$port" "$RESET" "$SYMBOL_CHECK"
    
    local nc_bin
    nc_bin=$(_get_netcat)
    
    if [[ -z "$nc_bin" ]]; then
        log_warning "No netcat available - cannot test FTP"
        SERVICES["$host:$port:ftp_supported"]="yes"
        return 0
    fi
    
    # Grab FTP banner
    local banner
    banner=$(echo "QUIT" | timeout "$NET_TIMEOUT" "$nc_bin" -nv "$host" "$port" 2>&1 | grep -E "^220|^221" | head -n1)
    
    if [[ -n "$banner" ]]; then
        printf '  %s├─ Banner: %s%s%s\n' "$GRAY" "$CYAN" "$banner" "$RESET"
        SERVICES["$host:$port:ftp_banner"]="$banner"
        
        # Check for vsftpd 2.3.4 (backdoor vulnerability)
        if [[ "$banner" == *"vsftpd 2.3.4"* ]]; then
            log_vuln "HIGH" "${SYMBOL_FIRE} vsftpd 2.3.4 BACKDOOR vulnerability!"
            VULNS["ftp-backdoor:$host:$port"]="vsftpd 2.3.4 Backdoor (CVE-2011-2523)"
            CONFIDENCE["ftp-backdoor:$host:$port"]="HIGH"
            EVIDENCE["ftp-backdoor:$host:$port"]="FTP Banner: $banner"
        fi
        
        # Check for ProFTPD vulnerabilities
        if [[ "$banner" == *"ProFTPD 1.3.5"* ]]; then
            log_vuln "HIGH" "${SYMBOL_FIRE} ProFTPD 1.3.5 mod_copy vulnerability!"
            VULNS["ftp-proftpd:$host:$port"]="ProFTPD 1.3.5 mod_copy RCE"
            CONFIDENCE["ftp-proftpd:$host:$port"]="HIGH"
            EVIDENCE["ftp-proftpd:$host:$port"]="FTP Banner: $banner"
        fi
    fi
    
    # Test anonymous login (skip in stealth mode)
    if [[ "$STEALTH_MODE" -eq 1 ]]; then
        printf '  %s├─ %sStealth mode: Skipping anonymous login test%s\n' \
            "$GRAY" "$YELLOW" "$RESET"
    else
        log_info "Testing anonymous FTP login..."
        
        local ftp_response
        ftp_response=$(printf 'USER anonymous\r\nPASS anonymous@example.com\r\nQUIT\r\n' | \
                       timeout "$NET_TIMEOUT" "$nc_bin" -nv "$host" "$port" 2>&1)
        
        if echo "$ftp_response" | grep -qE "^230"; then
            printf '  %s├─ %s%s ANONYMOUS LOGIN ALLOWED! %s%s\n' \
                "$GRAY" "$RED$BOLD" "$SYMBOL_UNLOCK" "$RESET" "$SYMBOL_FIRE"
            
            log_vuln "HIGH" "FTP Anonymous Login ALLOWED on $host:$port"
            
            VULNS["ftp-anon:$host:$port"]="FTP Anonymous Login Allowed"
            CONFIDENCE["ftp-anon:$host:$port"]="HIGH"
            EVIDENCE["ftp-anon:$host:$port"]="FTP 230 response - anonymous login successful"
            
            # Try to list directory
            local dir_list
            dir_list=$(printf 'USER anonymous\r\nPASS anonymous@example.com\r\nPASV\r\nLIST\r\nQUIT\r\n' | \
                       timeout "$NET_TIMEOUT" "$nc_bin" -nv "$host" "$port" 2>&1 | grep -E "^-|^d|^l" | head -5)
            
            if [[ -n "$dir_list" ]]; then
                printf '  %s├─ %sDirectory listing preview:%s\n' "$GRAY" "$DIM" "$RESET"
                echo "$dir_list" | while IFS= read -r line; do
                    printf '  %s│   %s%s%s\n' "$GRAY" "$DIM" "$line" "$RESET"
                done
            fi
            
        elif echo "$ftp_response" | grep -qE "^530|^530"; then
            printf '  %s├─ %sAnonymous login DENIED (530)%s\n' \
                "$GRAY" "$GREEN" "$RESET"
        else
            printf '  %s├─ %sAnonymous login status unclear%s\n' \
                "$GRAY" "$YELLOW" "$RESET"
        fi
    fi
    
    # Add to attack surface
    ATTACK_SURFACE+=("$port:FTP:auth:MEDIUM")
    
    printf '  %s└─ %sFTP login surface available%s %s\n' \
        "$GRAY" "$GREEN" "$RESET" "$SYMBOL_UNLOCK"
    
    log_success "FTP check complete for $host:$port"
    
    SERVICES["$host:$port:ftp_supported"]="yes"
    
    return 0
}

#───────────────────────────────────────────────────────────────────────────────
# MODULE: PROTOCOL SUPPORT SUMMARY
#───────────────────────────────────────────────────────────────────────────────

module_protocol_summary() {
    local host="$1"
    
    section_header "PROTOCOL SUPPORT SUMMARY"
    
    printf '  %s┌────────────────────────────────────────────────────┐%s\n' "$CYAN" "$RESET"
    printf '  %s│%s  %-20s │ %-10s │ %-10s %s│%s\n' \
        "$CYAN" "$BOLD" "PROTOCOL" "STATUS" "PORT" "$RESET$CYAN" "$RESET"
    printf '  %s├────────────────────────────────────────────────────┤%s\n' "$CYAN" "$RESET"
    
    # Check SSH
    local ssh_status="NOT FOUND"
    local ssh_port="-"
    local ssh_color="$RED"
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == "$host:"*":ssh_supported" ]]; then
            ssh_status="AVAILABLE"
            ssh_port=$(echo "$key" | cut -d: -f2)
            ssh_color="$GREEN"
            break
        fi
    done
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == "$host:"*":service" && "${SERVICES[$key]}" == *"ssh"* ]]; then
            ssh_status="AVAILABLE"
            ssh_port=$(echo "$key" | cut -d: -f2)
            ssh_color="$GREEN"
            break
        fi
    done
    printf '  %s│%s  %-20s │ %s%-10s%s │ %-10s %s│%s\n' \
        "$CYAN" "$RESET" "SSH" "$ssh_color" "$ssh_status" "$RESET" "$ssh_port" "$CYAN" "$RESET"
    
    # Check FTP
    local ftp_status="NOT FOUND"
    local ftp_port="-"
    local ftp_color="$RED"
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == "$host:"*":ftp_supported" ]]; then
            ftp_status="AVAILABLE"
            ftp_port=$(echo "$key" | cut -d: -f2)
            ftp_color="$GREEN"
            break
        fi
    done
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == "$host:"*":service" && "${SERVICES[$key]}" == *"ftp"* ]]; then
            ftp_status="AVAILABLE"
            ftp_port=$(echo "$key" | cut -d: -f2)
            ftp_color="$GREEN"
            break
        fi
    done
    printf '  %s│%s  %-20s │ %s%-10s%s │ %-10s %s│%s\n' \
        "$CYAN" "$RESET" "FTP" "$ftp_color" "$ftp_status" "$RESET" "$ftp_port" "$CYAN" "$RESET"
    
    # Check HTTP
    local http_status="NOT FOUND"
    local http_port="-"
    local http_color="$RED"
    if [[ ${#LIVE_HOSTS[@]} -gt 0 ]]; then
        http_status="AVAILABLE"
        http_port="80/443"
        http_color="$GREEN"
    fi
    printf '  %s│%s  %-20s │ %s%-10s%s │ %-10s %s│%s\n' \
        "$CYAN" "$RESET" "HTTP/HTTPS" "$http_color" "$http_status" "$RESET" "$http_port" "$CYAN" "$RESET"
    
    # Check for anonymous FTP
    local anon_status="N/A"
    local anon_color="$GRAY"
    for key in "${!VULNS[@]}"; do
        if [[ "$key" == "ftp-anon:$host:"* ]]; then
            anon_status="ALLOWED!"
            anon_color="$RED$BOLD"
            break
        fi
    done
    if [[ "$ftp_status" == "AVAILABLE" && "$anon_status" == "N/A" ]]; then
        anon_status="DENIED"
        anon_color="$GREEN"
    fi
    printf '  %s│%s  %-20s │ %s%-10s%s │ %-10s %s│%s\n' \
        "$CYAN" "$RESET" "FTP Anonymous" "$anon_color" "$anon_status" "$RESET" "-" "$CYAN" "$RESET"
    
    printf '  %s└────────────────────────────────────────────────────┘%s\n' "$CYAN" "$RESET"
}

#───────────────────────────────────────────────────────────────────────────────
# MASTER FUNCTION: RUN ALL EXTRA RECON
#───────────────────────────────────────────────────────────────────────────────

module_recon_extras() {
    local target="$1"
    
    section_header "🔍 RECON EXTRAS MODULE - by Hammad Naeem"
    
    log_info "Running extended reconnaissance on ${CYAN}$target${RESET}"
    printf '\n'
    
    # Extract host for port checks
    local host
    if [[ "$TARGET_TYPE" == "url" ]]; then
        host=$(_url_to_host "$target")
    else
        host="$target"
    fi
    
    #───────────────────────────────────────────────────────────────────────
    # 1. SSH Check
    #───────────────────────────────────────────────────────────────────────
    # Check if SSH port was found in nmap scan
    local ssh_found=0
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == "$host:"*":service" && "${SERVICES[$key]}" == *"ssh"* ]]; then
            local port=$(echo "$key" | cut -d: -f2)
            module_ssh_check "$host" "$port"
            ssh_found=1
        fi
    done
    
    # If no SSH in nmap, check default port 22
    if [[ $ssh_found -eq 0 ]]; then
        module_ssh_check "$host" "22"
    fi
    
    #───────────────────────────────────────────────────────────────────────
    # 2. FTP Check
    #───────────────────────────────────────────────────────────────────────
    local ftp_found=0
    for key in "${!SERVICES[@]}"; do
        if [[ "$key" == "$host:"*":service" && "${SERVICES[$key]}" == *"ftp"* ]]; then
            local port=$(echo "$key" | cut -d: -f2)
            module_ftp_check "$host" "$port"
            ftp_found=1
        fi
    done
    
    # If no FTP in nmap, check default port 21
    if [[ $ftp_found -eq 0 ]]; then
        module_ftp_check "$host" "21"
    fi
    
    #───────────────────────────────────────────────────────────────────────
    # 3. Gobuster Directory Enumeration (on HTTP hosts)
    #───────────────────────────────────────────────────────────────────────
    if [[ ${#LIVE_HOSTS[@]} -gt 0 ]]; then
        for url in "${LIVE_HOSTS[@]}"; do
            module_gobuster_enum "$url"
        done
    else
        # Try default HTTP/HTTPS
        for proto in "http" "https"; do
            local test_url="${proto}://${host}"
            local status_code
            status_code=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$test_url" 2>/dev/null)
            
            if [[ "$status_code" =~ ^[23] ]]; then
                log_info "Found live host: $test_url"
                module_gobuster_enum "$test_url"
                break
            fi
        done
    fi
    
    #───────────────────────────────────────────────────────────────────────
    # 4. Protocol Summary
    #───────────────────────────────────────────────────────────────────────
    module_protocol_summary "$host"
    
    log_success "Recon Extras module complete"
}

#───────────────────────────────────────────────────────────────────────────────
# AUTO-INTEGRATION: Register for automatic execution
#───────────────────────────────────────────────────────────────────────────────

# This function will be called by the main script if it exists
register_extension() {
    echo "recon_extras"
}

# Export the main module function
export -f module_recon_extras 2>/dev/null || true
