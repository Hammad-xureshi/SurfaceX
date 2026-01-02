#!/usr/bin/env bash
#───────────────────────────────────────────────────────────────────────────────
# MODULE: Intelligence Aggregator - Live Guidance System
#───────────────────────────────────────────────────────────────────────────────

# Attack path recommendations based on findings
declare -gA ATTACK_GUIDANCE=(
    ["database_exposure"]="
    ${BOLD}Database Exposure Detected${RESET}
    ${CYAN}Recommended Actions:${RESET}
    1. Check for default credentials
    2. Test for authentication bypass
    3. Look for backup files (.sql, .dump)
    4. Check for publicly accessible admin interfaces
    ${YELLOW}Note: Only passive testing - no active exploitation${RESET}"
    
    ["container_exposure"]="
    ${BOLD}Container/Orchestration Exposure${RESET}
    ${CYAN}Recommended Actions:${RESET}
    1. Check API authentication status
    2. Look for service account tokens
    3. Enumerate available resources
    4. Check for misconfigurations
    ${RED}High-value target - proceed carefully${RESET}"
    
    ["cicd_exposure"]="
    ${BOLD}CI/CD Pipeline Exposure${RESET}
    ${CYAN}Recommended Actions:${RESET}
    1. Check for anonymous access
    2. Look for exposed build logs
    3. Check for credential leaks in configs
    4. Enumerate available projects
    ${RED}Critical exposure - immediate attention required${RESET}"
    
    ["git_exposure"]="
    ${BOLD}Source Code Repository Exposure${RESET}
    ${CYAN}Recommended Actions:${RESET}
    1. Attempt to reconstruct repository
    2. Check for sensitive files in history
    3. Look for hardcoded credentials
    4. Analyze for vulnerability patterns
    ${RED}Critical data exposure${RESET}"
    
    ["auth_surface"]="
    ${BOLD}Authentication Surface Identified${RESET}
    ${CYAN}Recommended Actions:${RESET}
    1. Test for username enumeration
    2. Check password policy
    3. Look for default credentials
    4. Test for rate limiting
    5. Check for multi-factor authentication"
    
    ["api_exposure"]="
    ${BOLD}API Exposure Detected${RESET}
    ${CYAN}Recommended Actions:${RESET}
    1. Check for API documentation
    2. Test authentication requirements
    3. Look for parameter pollution
    4. Check for IDOR vulnerabilities
    5. Test rate limiting"
)

# Live guidance engine
provide_guidance() {
    section_header "INTELLIGENCE & GUIDANCE"
    
    local -a identified_paths=()
    
    # Analyze findings and determine attack paths
    for key in "${!VULNS[@]}"; do
        local vuln="${VULNS[$key]}"
        local conf="${CONFIDENCE[$key]}"
        
        # Categorize into attack paths
        case "$key" in
            *mysql*|*postgres*|*mongo*|*redis*)
                [[ ! " ${identified_paths[*]} " =~ " database_exposure " ]] && \
                    identified_paths+=("database_exposure")
                ;;
            *docker*|*kubernetes*|*kubelet*)
                [[ ! " ${identified_paths[*]} " =~ " container_exposure " ]] && \
                    identified_paths+=("container_exposure")
                ;;
            *jenkins*|*gitlab*|*bamboo*|*travis*)
                [[ ! " ${identified_paths[*]} " =~ " cicd_exposure " ]] && \
                    identified_paths+=("cicd_exposure")
                ;;
            *git*|*svn*)
                [[ ! " ${identified_paths[*]} " =~ " git_exposure " ]] && \
                    identified_paths+=("git_exposure")
                ;;
            *401*|*auth*|*login*)
                [[ ! " ${identified_paths[*]} " =~ " auth_surface " ]] && \
                    identified_paths+=("auth_surface")
                ;;
            *swagger*|*graphql*|*api*)
                [[ ! " ${identified_paths[*]} " =~ " api_exposure " ]] && \
                    identified_paths+=("api_exposure")
                ;;
        esac
    done
    
    # Display guidance for identified paths
    if [[ ${#identified_paths[@]} -gt 0 ]]; then
        log_info "Generating actionable guidance based on findings..."
        printf '\n'
        
        for path in "${identified_paths[@]}"; do
            if [[ -n "${ATTACK_GUIDANCE[$path]}" ]]; then
                printf '%s\n' "  ╔══════════════════════════════════════════════════════════════╗"
                printf '%b\n' "${ATTACK_GUIDANCE[$path]}" | sed 's/^/  ║ /'
                printf '%s\n\n' "  ╚══════════════════════════════════════════════════════════════╝"
            fi
        done
    else
        log_info "No high-priority attack paths identified - continue manual analysis"
    fi
}

# Contextual intelligence based on combined signals
analyze_context() {
    local -A context_signals=()
    
    # Count signal types
    for key in "${!SERVICES[@]}"; do
        local service="${SERVICES[$key]}"
        case "$service" in
            *http*|*nginx*|*apache*) ((context_signals[web]++)) ;;
            *ssh*) ((context_signals[remote_access]++)) ;;
            *ftp*) ((context_signals[file_transfer]++)) ;;
            *sql*|*database*) ((context_signals[database]++)) ;;
        esac
    done
    
    printf '\n  %s%sContext Analysis:%s\n' "$BOLD" "$CYAN" "$RESET"
    
    # Web-heavy context
    if [[ ${context_signals[web]:-0} -gt 2 ]]; then
        printf '  %s├─ Web-heavy infrastructure detected%s\n' "$GRAY" "$RESET"
        printf '  %s│  Focus: Web application security testing%s\n' "$DIM" "$RESET"
    fi
    
    # Mixed infrastructure
    if [[ ${context_signals[database]:-0} -gt 0 && ${context_signals[web]:-0} -gt 0 ]]; then
        printf '  %s├─ Web+Database infrastructure%s\n' "$GRAY" "$RESET"
        printf '  %s│  Focus: SQL injection, data exposure%s\n' "$DIM" "$RESET"
    fi
    
    # Remote access available
    if [[ ${context_signals[remote_access]:-0} -gt 0 ]]; then
        printf '  %s└─ Remote access services available%s\n' "$GRAY" "$RESET"
        printf '  %s   Focus: Credential testing, auth bypass%s\n' "$DIM" "$RESET"
    fi
}
