#!/usr/bin/env bash
#───────────────────────────────────────────────────────────────────────────────
# MODULE: Advanced Path Discovery (Integrated with Knowledge Engine)
#───────────────────────────────────────────────────────────────────────────────

# Critical paths to check (non-intrusive, passive discovery)
declare -ga CRITICAL_PATHS=(
    "/.git/HEAD"
    "/.git/config"
    "/.svn/entries"
    "/.env"
    "/.env.local"
    "/.env.production"
    "/wp-config.php.bak"
    "/wp-config.php.old"
    "/config.php.bak"
    "/server-status"
    "/server-info"
    "/phpinfo.php"
    "/info.php"
    "/.htaccess"
    "/.htpasswd"
    "/robots.txt"
    "/sitemap.xml"
    "/crossdomain.xml"
    "/clientaccesspolicy.xml"
    "/.well-known/security.txt"
    "/api/swagger.json"
    "/api/swagger.yaml"
    "/swagger.json"
    "/openapi.json"
    "/graphql"
    "/graphiql"
    "/actuator"
    "/actuator/health"
    "/actuator/env"
    "/actuator/heapdump"
    "/metrics"
    "/debug"
    "/trace"
    "/admin"
    "/administrator"
    "/manager/html"
    "/jmx-console"
    "/web-console"
    "/invoker/JMXInvokerServlet"
    "/console"
    "/.DS_Store"
    "/Thumbs.db"
    "/backup"
    "/backup.zip"
    "/backup.tar.gz"
    "/db.sql"
    "/database.sql"
    "/dump.sql"
)

module_path_discovery() {
    local base_url="$1"
    section_header "PATH DISCOVERY (Knowledge-Based)"
    
    log_info "Checking ${#CRITICAL_PATHS[@]} critical paths on ${CYAN}$base_url${RESET}"
    log_warning "Using HEAD requests only - minimal footprint"
    
    local found_count=0
    local checked_count=0
    local total=${#CRITICAL_PATHS[@]}
    
    for path in "${CRITICAL_PATHS[@]}"; do
        ((checked_count++))
        
        # Use HEAD request for minimal footprint
        local response
        response=$(curl -sI -o /dev/null -w "%{http_code}" -m 3 "${base_url}${path}" 2>/dev/null)
        
        # Update progress
        printf '\r  Checking: [%d/%d] %s' "$checked_count" "$total" "$path"
        
        # Analyze response
        case "$response" in
            200)
                ((found_count++))
                printf '\n  %s%s%s %s%s%s → %s200 OK%s\n' \
                    "$GREEN" "$SYMBOL_CHECK" "$RESET" \
                    "$CYAN" "$path" "$RESET" \
                    "$GREEN" "$RESET"
                
                # Apply knowledge patterns
                local pattern_key="path:$path"
                if [[ -n "${KNOWLEDGE_PATTERNS[$pattern_key]}" ]]; then
                    IFS='|' read -r name desc weight vector <<< "${KNOWLEDGE_PATTERNS[$pattern_key]}"
                    
                    local confidence="LOW"
                    ((weight >= 7)) && confidence="HIGH"
                    ((weight >= 4 && weight < 7)) && confidence="MEDIUM"
                    
                    VULNS["path:$path:$base_url"]="$desc"
                    CONFIDENCE["path:$path:$base_url"]="$confidence"
                    EVIDENCE["path:$path:$base_url"]="Accessible at ${base_url}${path}"
                    
                    log_vuln "$confidence" "$desc"
                fi
                ;;
            403)
                # Forbidden but exists
                printf '\n  %s%s%s %s%s%s → %s403 Forbidden%s (exists but protected)\n' \
                    "$YELLOW" "$SYMBOL_WARN" "$RESET" \
                    "$DIM" "$path" "$RESET" \
                    "$YELLOW" "$RESET"
                ;;
            301|302)
                printf '\n  %s%s%s %s%s%s → %s%s Redirect%s\n' \
                    "$CYAN" "$SYMBOL_ARROW" "$RESET" \
                    "$DIM" "$path" "$RESET" \
                    "$CYAN" "$response" "$RESET"
                ;;
        esac
    done
    
    printf '\r%*s\r' 80 ""  # Clear progress line
    log_success "Path discovery complete: ${GREEN}$found_count${RESET} interesting paths found"
}

# Integration function for main script
integrate_path_discovery() {
    for url in "${LIVE_HOSTS[@]}"; do
        module_path_discovery "$url"
    done
}
