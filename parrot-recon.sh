#!/usr/bin/env bash

# WARNING! This tool is incredibly invasive and will make a lot of noise on a network. It
# is designed for bug bounties, not pentests involving a blue team. Please be careful when
# using this tool. DISCLAIMER: I WILL NOT BE HELD RESPONSIBLE FOR ANY ILLEGAL ACTIVITY
# YOU DECIDE TO DO WITH THIS TOOL. IT WAS MADE FOR ETHICAL PURPOSES. PLEASE BE CAREFUL!

# banner
cat << "EOF"
   ___                    __        ___
  / _ \___ ____________  / /____   / _ \___ _______  ___
 / ___/ _ `/ __/ __/ _ \/ __(_-<  / , _/ -_) __/ _ \/ _ \
/_/   \_,_/_/ /_/  \___/\__/___/ /_/|_|\__/\__/\___/_//_/

   /.\
   |  \
   /   \
  //  /
  |/ /\__________________________________________________
 / /
/ /
\/
EOF

set -o pipefail

# defines environment variables and terminal colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    red=$(tput setaf 1)
    green=$(tput setaf 2)
    blue=$(tput setaf 4)
    yellow=$(tput setaf 3)
    reset=$(tput sgr0)
else
    red=""; green=""; blue=""; yellow=""; reset=""
fi

working_dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
results_dir=$working_dir/results
tools_dir=$working_dir/tools
tmp_dir=$(mktemp -d -t parrot-recon.XXXXXX)

# Default options
server_port=${RECON_PORT:-8098}
enable_server=0
enable_udp=0
mail_recipient=""
api_collection=""
domain=""
type=""
wordlist=""

scan_start_time=$(date +%s)
scan_start_date=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# every step that fails lands here so the run can finish and still report honestly
declare -a failed_steps=()
declare -a skipped_steps=()

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

format_newline() {
    printf "\n"
}

info() { echo "${blue}[*]${reset} $*"; }
step() { echo "${red}[+]${reset} $*"; }
ok()   { echo "${green}[+]${reset} $*"; }
warn() { echo "${yellow}[!]${reset} $*"; }
err()  { echo "${red}[-]${reset} $*"; }

# returns 0 if a command exists on PATH
have() {
    command -v "$1" >/dev/null 2>&1
}

# skip a step loudly instead of running a missing binary and producing an empty file
require_tool() {
    local tool=$1 label=$2
    if have "$tool"; then
        return 0
    fi
    warn "Skipping ${label}: '${tool}' is not installed (run the install script for your platform)"
    skipped_steps+=("$label (missing: $tool)")
    return 1
}

# runs a scan step, records the failure, never aborts the rest of the run
run_step() {
    local label=$1; shift
    local rc=0
    "$@" || rc=$?
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    err "${label} failed (exit $rc)"
    failed_steps+=("$label")
    return 1
}

# several tools exit 0 having written nothing at all - confirm the artifact exists
saved() {
    local msg=$1 file=$2
    if [ -s "$file" ]; then
        ok "$msg"
        return 0
    fi
    warn "No output written to $file (the tool reported success but produced nothing)"
    return 1
}

# sslyze exits non-zero whenever a scan command reports a problem
run_sslyze() {
    local label=$1 out=$2; shift 2
    sslyze "$@" > "$out" 2>&1
    if grep -q 'SCAN RESULTS' "$out"; then
        return 0
    fi
    err "${label} failed (no scan results in report)"
    failed_steps+=("$label")
    return 1
}

# Usage function
usage() {
    format_newline
    echo "${green}Usage:${reset} $0 -d <domain> -t <scan-type> [options]"
    format_newline
    echo "Scan Types:"
    echo "  ${red}API${reset} - Enumerates an API and finds common misconfigurations (requires -c)"
    echo "  ${red}WEB${reset} - Enumerates a Web Application and runs vulnerability scanning"
    echo "  ${red}ALL${reset} - Performs both API and Web enumeration"
    format_newline
    echo "Options:"
    echo "  -d <domain>      Target domain (required)"
    echo "  -t <type>        Scan type: API | WEB | ALL (required, case insensitive)"
    echo "  -w <wordlist>    Wordlist for content discovery (optional, WEB/ALL)"
    echo "  -c <collection>  API collection file: .json (Postman) or .yaml/.yml (OpenAPI) - required for API"
    echo "  -m <email>       Recipient email for completion notification via Mailgun"
    echo "  -s               Launch local Results Web Server & WebDAV Explorer upon completion"
    echo "  -p <port>        Port for Results Web Server (default: 8098)"
    echo "  -u               Enable Nmap UDP port scan (scans top 100 ports)"
    echo "  -o <dir>         Custom output directory (default: results/)"
    echo "  -h               Show this help menu"
    format_newline
    echo "Environment Variables:"
    echo "  MAILGUN_API_KEY  Mailgun Private API Key"
    echo "  MAILGUN_DOMAIN   Mailgun Sending Domain"
    echo "  MAILGUN_TO       Default recipient email"
    echo "  MAILGUN_REGION   Mailgun API region: 'us' (default) or 'eu'"
    echo "  RECON_PORT       Default port for results web server (default: 8098)"
    echo "  CMSMAP_FULL      Set to 1 to enable cmsmap fullscan (-F)"
    exit 0
}

# picks http vs https once instead of running every tool twice and hoping
detect_scheme() {
    local d=$1
    if curl -s -k -m 15 -o /dev/null "https://$d"; then
        echo "https"
    elif curl -s -m 15 -o /dev/null "http://$d"; then
        echo "http"
    else
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# API scanning
# ---------------------------------------------------------------------------

# pulls URLs out of a Postman collection or an OpenAPI/Swagger spec
extract_api_urls() {
    local collection=$1 out=$2

    case "$collection" in
        *.json)
            info "JSON collection detected. Extracting URLs from $collection"
            grep -oE '"(raw|url)"[[:space:]]*:[[:space:]]*"https?://[^"]+"' "$collection" \
                | grep -oE 'https?://[^"]+' \
                | grep -v '{{' \
                | sort -u > "$out"
            ;;
        *.yaml|*.yml)
            info "YAML collection detected. Extracting URLs from $collection"
            grep -oE 'https?://[^"'"'"' ]+' "$collection" \
                | sed 's/[,]*$//' \
                | grep -v '{{' \
                | sort -u > "$out"
            ;;
        *)
            err "Unsupported collection format: $collection (expected .json or .yaml/.yml)"
            return 1
            ;;
    esac

    if [ ! -s "$out" ]; then
        err "No absolute URLs found in $collection (Postman {{baseUrl}} variables cannot be resolved)"
        return 1
    fi
    return 0
}

api_scan() {
    format_newline
    step "Starting API Scanning"

    if [ -z "$api_collection" ]; then
        err "API scan needs a collection file: -c <collection.json|collection.yaml>"
        failed_steps+=("API scan (no -c collection supplied)")
        return 1
    fi

    if [ ! -f "$api_collection" ]; then
        err "Collection file not found: $api_collection"
        failed_steps+=("API scan (collection not found)")
        return 1
    fi

    local api_urls=$results_dir/$domain-api-urls.txt
    if ! extract_api_urls "$api_collection" "$api_urls"; then
        failed_steps+=("API URL extraction")
        return 1
    fi
    ok "URLs extracted and saved to: $api_urls"

    # unique hostnames for host-level scans
    local api_hosts=$tmp_dir/api-hosts.txt
    awk -F/ '{print $3}' "$api_urls" | cut -d: -f1 | sort -u > "$api_hosts"
    info "$(wc -l < "$api_urls") URL(s) across $(wc -l < "$api_hosts") host(s)"

    local scanned
    if require_tool nmap "Nmap API vuln scan"; then
        step "Starting Nmap Script Vuln Enumeration on API Endpoints"
        scanned=0
        while read -r api_host; do
            [ -n "$api_host" ] || continue
            run_step "Nmap vuln scan ($api_host)" \
                nmap -sV -sC -p 443 --script=vuln -oA "$results_dir/nmap-api-vuln-$api_host" "$api_host" \
                && scanned=$((scanned + 1))
        done < "$api_hosts"
        [ "$scanned" -gt 0 ] \
            && ok "Nmap Script Vuln Enumeration Saved To: $results_dir/nmap-api-vuln-<host>.* ($scanned host(s))"
    fi

    if require_tool nikto "Nikto API scan"; then
        step "Starting Nikto Scan for API"
        scanned=0
        while read -r api_host; do
            [ -n "$api_host" ] || continue
            rm -f "$results_dir/nikto-api-$api_host.txt"
            run_step "Nikto ($api_host)" \
                nikto -h "$api_host" -Format txt -o "$results_dir/nikto-api-$api_host" \
                && scanned=$((scanned + 1))
        done < "$api_hosts"
        [ "$scanned" -gt 0 ] \
            && ok "Nikto Scan Saved To: $results_dir/nikto-api-<host>.txt ($scanned host(s))"
    fi

    if require_tool curl "Authentication bypass check"; then
        step "Checking for Authentication Bypass"
        local authfile=$results_dir/$domain-api-authcheck.txt
        : > "$authfile"
        echo "----------------- Results -------------------"
        while read -r api_url; do
            [ -n "$api_url" ] || continue
            local response
            response=$(curl -s -k -m 20 -o /dev/null -w "%{http_code}" "$api_url")
            echo "$api_url - $response" | tee -a "$authfile"
            if [ "$response" = "200" ]; then
                err "Authentication bypass may be possible -> $api_url"
                echo "  [-] unauthenticated 200, auth bypass may be possible" >> "$authfile"
            elif [ "$response" = "000" ]; then
                warn "No response from $api_url"
                echo "  [!] no response" >> "$authfile"
            else
                ok "Authentication bypass may not be possible -> $api_url"
            fi
        done < "$api_urls"
        ok "Auth Bypass Results Saved To: $authfile"
    fi

    return 0
}

# ---------------------------------------------------------------------------
# WEB scanning
# ---------------------------------------------------------------------------

sql_probe() {
    local target=$1
    local bin=$tmp_dir/parrot-sqltest

    if ! (cd "$tools_dir" && go build -o "$bin" . >/dev/null 2>&1); then
        err "Could not build $tools_dir/main.go (is the gotabulate module available?)"
        return 1
    fi

    "$bin" -t "$target" 2>&1 | tee "$results_dir/$domain-sqlerror-probe.txt"
    return 0
}

web_scan() {
    format_newline
    step "Starting Website Enumeration"

    local target=$scheme://$domain

    if require_tool go "Go SQL error probe"; then
        run_step "SQL error probe" sql_probe "$target" \
            && saved "SQL Error Probe Saved To: $results_dir/$domain-sqlerror-probe.txt" "$results_dir/$domain-sqlerror-probe.txt"
    fi

    if require_tool lynx "URL DORK scan"; then
        step "Starting URL DORK Scan"
        run_step "URL dork scan" bash "$tools_dir/dork.sh" "$domain" "$results_dir/$domain-dork.txt" \
            && saved "URL DORK Scan Saved To: $results_dir/$domain-dork.txt" "$results_dir/$domain-dork.txt"
    fi

    if require_tool nmap "Nmap TCP scan"; then
        step "Starting Nmap TCP Scan"
        run_step "Nmap TCP scan" \
            nmap -sV -sC "$domain" -oA "$results_dir/$domain-tcp-scan" --open \
            && ok "Nmap TCP Scan Saved To: $results_dir/$domain-tcp-scan.*"
    fi

    if [ "$enable_udp" -eq 1 ]; then
        if require_tool nmap "Nmap UDP scan"; then
            step "Starting Nmap UDP Scan (Top 100 Ports)"
            run_step "Nmap UDP scan" \
                nmap -sV -sU --top-ports 100 "$domain" -oA "$results_dir/$domain-udp-scan" --open \
                && ok "Nmap UDP Scan Saved To: $results_dir/$domain-udp-scan.*"
        fi
    fi

    if require_tool wafw00f "IDS/IPS detection"; then
        step "Starting IDS/IPS Detection"
        run_step "wafw00f" wafw00f "$target" -o "$results_dir/wafw00f-$domain.txt" \
            && saved "IDS/IPS Results Saved To: $results_dir/wafw00f-$domain.txt" "$results_dir/wafw00f-$domain.txt"
    fi

    if require_tool curl "Subdomain enumeration"; then
        step "Starting Subdomain Enumeration"
        run_step "subdomain enumeration" \
            bash "$tools_dir/subenum.sh" "$domain" "$results_dir/subdomains-$domain.txt" \
            && saved "Subdomains Saved To: $results_dir/subdomains-$domain.txt" \
                     "$results_dir/subdomains-$domain.txt"

        # If subdomains were found and subzy is installed, run subdomain takeover detection
        if [ -s "$results_dir/subdomains-$domain.txt" ] && have subzy; then
            step "Starting Subdomain Takeover Enumeration (subzy)"
            run_step "Subdomain takeover" \
                subzy run --targets "$results_dir/subdomains-$domain.txt" --hide_fails --verify_ssl > "$results_dir/takeover-$domain.txt" 2>&1 \
                && saved "Subdomain Takeover Results Saved To: $results_dir/takeover-$domain.txt" "$results_dir/takeover-$domain.txt"
        fi
    fi

    if require_tool nikto "Nikto scan"; then
        step "Starting Nikto Scan"
        rm -f "$results_dir/nikto-$domain.txt"
        run_step "Nikto" nikto -h "$domain" -Format txt -o "$results_dir/nikto-$domain" \
            && saved "Nikto Scan Saved To: $results_dir/nikto-$domain.txt" "$results_dir/nikto-$domain.txt"
    fi

    if require_tool cmsmap "CMS enumeration"; then
        step "Starting CMS Enumeration"
        rm -f "$results_dir/cmsenum-$domain.txt"
        cmsmap_args=(-s)
        [ "${CMSMAP_FULL:-0}" = "1" ] && cmsmap_args=(-F -s)
        run_step "cmsmap" cmsmap "${cmsmap_args[@]}" "$target" -o "$results_dir/cmsenum-$domain.txt" \
            && saved "CMS Enumeration Saved To: $results_dir/cmsenum-$domain.txt" "$results_dir/cmsenum-$domain.txt"
    fi

    if require_tool sslyze "SSL scans"; then
        step "Starting SSL Scans"
        run_sslyze "sslyze full scan" "$results_dir/$domain-sslyze-regular.txt" "$domain" \
            && saved "Regular SSL Scan Saved To: $results_dir/$domain-sslyze-regular.txt" "$results_dir/$domain-sslyze-regular.txt"
        run_sslyze "sslyze heartbleed" "$results_dir/$domain-sslyze-heartbleed.txt" --heartbleed "$domain" \
            && saved "HeartBleed Scan Saved To: $results_dir/$domain-sslyze-heartbleed.txt" "$results_dir/$domain-sslyze-heartbleed.txt"
        run_sslyze "sslyze robot" "$results_dir/$domain-sslyze-robot.txt" --robot "$domain" \
            && saved "Robot Scan Saved To: $results_dir/$domain-sslyze-robot.txt" "$results_dir/$domain-sslyze-robot.txt"
    fi

    if require_tool nuclei "Nuclei scans"; then
        step "Starting Nuclei Scans"
        run_step "nuclei" nuclei -u "$target" -o "$results_dir/nuclei-$domain.txt" \
            && saved "Nuclei Scans Saved To: $results_dir/nuclei-$domain.txt" "$results_dir/nuclei-$domain.txt"
    fi

    if require_tool python3 "Secure headers check"; then
        step "Starting Secure Headers Check"
        run_step "shcheck" \
            bash -c 'python3 "$1" "$2" > "$3" 2>&1' _ "$tools_dir/shcheck.py" "$target" "$results_dir/$domain-shcheck.txt" \
            && saved "Shcheck Results Saved To: $results_dir/$domain-shcheck.txt" "$results_dir/$domain-shcheck.txt"

        step "Starting CORS Enumeration"
        run_step "cors_scanner" \
            python3 "$tools_dir/cors_scanner.py" -u "$target" -csv "$results_dir/$domain-cors.csv" \
            && saved "CORS Enumeration Results Saved To: $results_dir/$domain-cors.csv" "$results_dir/$domain-cors.csv"
    fi

    local headi_bin=""
    for candidate in "$tools_dir/headi/headi" "$tools_dir/headi/main" "$tools_dir/headi-bin"; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            headi_bin=$candidate
            break
        fi
    done
    if [ -z "$headi_bin" ] && [ -f "$tools_dir/headi" ] && [ -x "$tools_dir/headi" ]; then
        headi_bin=$tools_dir/headi
    fi
    if [ -z "$headi_bin" ] && have headi; then
        headi_bin=$(command -v headi)
    fi

    if [ -n "$headi_bin" ]; then
        step "Starting HTTP HEADER INJECTION Enumeration"
        run_step "headi" \
            bash -c '"$1" -u "$2" > "$3" 2>&1' _ "$headi_bin" "$target/" "$results_dir/headi-$domain.txt" \
            && saved "HTTP HEADER INJECTION Results Saved To: $results_dir/headi-$domain.txt" "$results_dir/headi-$domain.txt"
    else
        warn "Skipping HTTP header injection: headi is not built (re-run the install script)"
        skipped_steps+=("HTTP header injection (missing: headi)")
    fi

    if [ -n "$wordlist" ]; then
        if [ ! -f "$wordlist" ]; then
            err "Wordlist not found: $wordlist"
            failed_steps+=("Content discovery (wordlist not found)")
        elif have ffuf; then
            step "Starting Content Discovery (ffuf)"
            run_step "ffuf" ffuf -u "$target/FUZZ" -w "$wordlist" -mc 200,201,204,301,302,307,401,403 \
                -o "$results_dir/$domain-content-discovery.json" -of json \
                && saved "Content Discovery Saved To: $results_dir/$domain-content-discovery.json" "$results_dir/$domain-content-discovery.json"
        elif have dirsearch; then
            step "Starting Content Discovery (dirsearch)"
            run_step "dirsearch" dirsearch -u "$target" -w "$wordlist" \
                -o "$results_dir/$domain-content-discovery.txt" \
                && saved "Content Discovery Saved To: $results_dir/$domain-content-discovery.txt" "$results_dir/$domain-content-discovery.txt"
        else
            warn "Skipping content discovery: neither ffuf nor dirsearch is installed"
            skipped_steps+=("Content discovery (missing: ffuf/dirsearch)")
        fi
    fi

    return 0
}

scan_all() {
    api_scan
    web_scan
}

# ---------------------------------------------------------------------------
# Executive Summary Report Generator
# ---------------------------------------------------------------------------
generate_summary() {
    local summary_md=$results_dir/$domain-summary.md
    local summary_html=$results_dir/$domain-summary.html
    local scan_end_time
    scan_end_time=$(date +%s)
    local scan_duration=$((scan_end_time - scan_start_time))
    local scan_end_date
    scan_end_date=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

    # Extract metrics
    local sub_count=0
    [ -f "$results_dir/subdomains-$domain.txt" ] && sub_count=$(wc -l < "$results_dir/subdomains-$domain.txt" 2>/dev/null || echo "0")

    local open_tcp_ports=""
    if [ -f "$results_dir/$domain-tcp-scan.nmap" ]; then
        open_tcp_ports=$(grep -E '^[0-9]+/tcp[[:space:]]+open' "$results_dir/$domain-tcp-scan.nmap" 2>/dev/null | awk '{print $1 " (" $3 ")"}' | paste -sd ", " -)
    fi
    [ -z "$open_tcp_ports" ] && open_tcp_ports="None detected"

    local open_udp_ports=""
    if [ -f "$results_dir/$domain-udp-scan.nmap" ]; then
        open_udp_ports=$(grep -E '^[0-9]+/udp[[:space:]]+open' "$results_dir/$domain-udp-scan.nmap" 2>/dev/null | awk '{print $1 " (" $3 ")"}' | paste -sd ", " -)
    fi
    [ -z "$open_udp_ports" ] && open_udp_ports="None / Not scanned"

    local nuclei_count=0
    local nuclei_high=0
    if [ -f "$results_dir/nuclei-$domain.txt" ]; then
        nuclei_count=$(wc -l < "$results_dir/nuclei-$domain.txt" 2>/dev/null || echo "0")
        nuclei_high=$(grep -E -i '\[(critical|high)\]' "$results_dir/nuclei-$domain.txt" 2>/dev/null | wc -l || echo "0")
    fi

    local waf_info="Unknown / None"
    if [ -f "$results_dir/wafw00f-$domain.txt" ]; then
        local waf_line
        waf_line=$(grep -E "(is behind|Site.*is protected)" "$results_dir/wafw00f-$domain.txt" 2>/dev/null | head -n 1)
        [ -n "$waf_line" ] && waf_info="$waf_line"
    fi

    local cms_info="Unknown / None"
    if [ -f "$results_dir/cmsenum-$domain.txt" ]; then
        local cms_line
        cms_line=$(grep -E "(WordPress|Joomla|Drupal|vBulletin)" "$results_dir/cmsenum-$domain.txt" 2>/dev/null | head -n 1)
        [ -n "$cms_line" ] && cms_info="$cms_line"
    fi

    local cors_findings="None"
    if [ -f "$results_dir/$domain-cors.csv" ]; then
        local cors_count
        cors_count=$(wc -l < "$results_dir/$domain-cors.csv" 2>/dev/null || echo "0")
        [ "$cors_count" -gt 1 ] && cors_findings="$((cors_count - 1)) potential misconfiguration(s) flagged"
    fi

    local api_urls_count=0
    [ -f "$results_dir/$domain-api-urls.txt" ] && api_urls_count=$(wc -l < "$results_dir/$domain-api-urls.txt" 2>/dev/null || echo "0")

    local api_auth_bypass=0
    if [ -f "$results_dir/$domain-api-authcheck.txt" ]; then
        api_auth_bypass=$(grep -c "unauthenticated 200" "$results_dir/$domain-api-authcheck.txt" 2>/dev/null || echo "0")
    fi

    # Build Markdown Summary
    cat << EOF > "$summary_md"
# Parrot Recon - Scan Summary Report

**Target Domain:** \`$domain\`  
**Target IP:** \`$ip_address\`  
**Scan Type:** \`$type\`  
**Resolved Scheme:** \`$scheme://$domain\`  
**Start Time:** $scan_start_date  
**Finish Time:** $scan_end_date  
**Scan Duration:** ${scan_duration}s  

---

## Executive Overview

| Metric | Result |
| :--- | :--- |
| **Discovered Subdomains** | $sub_count |
| **Open TCP Ports** | $open_tcp_ports |
| **Open UDP Ports** | $open_udp_ports |
| **WAF / IDS Detection** | $waf_info |
| **CMS Enumeration** | $cms_info |
| **Nuclei Vulnerabilities** | $nuclei_count ($nuclei_high Critical/High) |
| **CORS Findings** | $cors_findings |
| **API Endpoints Analyzed** | $api_urls_count |
| **Unauthenticated API Hits (200 OK)** | $api_auth_bypass |

---

## Scan Health & Execution

- **Failed Steps:** ${#failed_steps[@]}
- **Skipped Steps:** ${#skipped_steps[@]}

EOF

    if [ ${#failed_steps[@]} -gt 0 ]; then
        echo "### Failed Steps" >> "$summary_md"
        for s in "${failed_steps[@]}"; do echo "- $s" >> "$summary_md"; done
        echo "" >> "$summary_md"
    fi

    if [ ${#skipped_steps[@]} -gt 0 ]; then
        echo "### Skipped Steps" >> "$summary_md"
        for s in "${skipped_steps[@]}"; do echo "- $s" >> "$summary_md"; done
        echo "" >> "$summary_md"
    fi

    cat << EOF >> "$summary_md"
---

## Generated Artifacts

EOF
    for art in "$results_dir"/*"$domain"*; do
        if [ -f "$art" ]; then
            echo "- \`$(basename "$art")\` ($(du -h "$art" 2>/dev/null | cut -f1))" >> "$summary_md"
        fi
    done

    # Generate HTML summary
    cat << EOF > "$summary_html"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Parrot Recon Summary - $domain</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; line-height: 1.6; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; max-width: 900px; margin: 0 auto 20px auto; }
h1, h2, h3 { color: #f0f6fc; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; margin-top: 14px; }
th, td { padding: 10px 14px; border: 1px solid #30363d; text-align: left; }
th { background: #1f242c; color: #58a6ff; font-weight: 600; }
code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #79c0ff; }
</style>
</head>
<body>
<div class="card">
<h1>🦜 Parrot Recon Executive Summary</h1>
<p><strong>Target:</strong> <code>$domain</code> (<code>$ip_address</code>) | <strong>Scan Type:</strong> <code>$type</code> | <strong>Duration:</strong> ${scan_duration}s</p>
<hr style="border:0; border-top:1px solid #30363d; margin:16px 0;">
<h2>Findings Overview</h2>
<table>
<tr><th>Category</th><th>Finding / Status</th></tr>
<tr><td>Discovered Subdomains</td><td><strong>$sub_count</strong></td></tr>
<tr><td>Open TCP Ports</td><td>$open_tcp_ports</td></tr>
<tr><td>Open UDP Ports</td><td>$open_udp_ports</td></tr>
<tr><td>WAF / IDS Status</td><td>$waf_info</td></tr>
<tr><td>CMS Detection</td><td>$cms_info</td></tr>
<tr><td>Nuclei Vulnerability Alerts</td><td><strong>$nuclei_count</strong> ($nuclei_high Critical/High)</td></tr>
<tr><td>CORS Misconfigurations</td><td>$cors_findings</td></tr>
<tr><td>API Endpoints Enumerated</td><td>$api_urls_count</td></tr>
<tr><td>Unauthenticated API Responses (200)</td><td><strong>$api_auth_bypass</strong></td></tr>
</table>
</div>
</body>
</html>
EOF

    ok "Executive summary generated: $summary_md"
}

# ---------------------------------------------------------------------------
# Mailgun Notification Dispatcher
# ---------------------------------------------------------------------------
dispatch_email() {
    local recipient="${mail_recipient:-${MAILGUN_TO:-}}"
    if [ -z "$recipient" ]; then
        return 0
    fi

    format_newline
    step "Dispatching Scan Completion Email via Mailgun"
    if [ -z "${MAILGUN_API_KEY:-}" ] || [ -z "${MAILGUN_DOMAIN:-}" ]; then
        warn "Mailgun notifications requested for '$recipient', but MAILGUN_API_KEY or MAILGUN_DOMAIN is unset."
        warn "Export these environment variables to activate automated email delivery."
        skipped_steps+=("Mailgun notification (missing credentials)")
        return 0
    fi

    if require_tool python3 "Mailgun email dispatcher"; then
        run_step "Mailgun notification" \
            python3 "$working_dir/mailserver/sendemail.py" \
                -d "$domain" \
                -t "$type" \
                -m "$recipient" \
                --summary-file "$results_dir/$domain-summary.md" \
                --html-file "$results_dir/$domain-summary.html" \
                --results-dir "$results_dir" \
            && ok "Completion email dispatched to $recipient"
    fi
}

# ---------------------------------------------------------------------------
# Local Results Web Server / WebDAV Launcher
# ---------------------------------------------------------------------------
launch_server() {
    if [ "$enable_server" -eq 1 ]; then
        format_newline
        step "Starting Local Results Web Server & WebDAV Explorer"
        info "Results Dashboard URL: http://127.0.0.1:$server_port/"
        info "Press Ctrl+C to terminate the server when finished viewing results."
        python3 "$working_dir/webdav/serve_results.py" -p "$server_port" -d "$results_dir"
    fi
}

# ---------------------------------------------------------------------------
# Fix File Permissions
# ---------------------------------------------------------------------------
fix_permissions() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        local user_group
        user_group=$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")
        chown -R "$SUDO_USER:$user_group" "$results_dir" 2>/dev/null \
            && info "Adjusted ownership of $results_dir to $SUDO_USER:$user_group"
    fi
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

while getopts ":d:t:w:c:m:p:o:ush" opt; do
    case ${opt} in
        d )
            domain=${OPTARG}
            ;;
        t )
            type=${OPTARG}
            ;;
        w )
            wordlist=${OPTARG}
            ;;
        c )
            api_collection=${OPTARG}
            ;;
        m )
            mail_recipient=${OPTARG}
            ;;
        s )
            enable_server=1
            ;;
        p )
            server_port=${OPTARG}
            ;;
        u )
            enable_udp=1
            ;;
        o )
            results_dir=${OPTARG}
            ;;
        h )
            usage
            ;;
        \? )
            echo "${red}Invalid option: -${OPTARG}${reset}" >&2
            usage
            ;;
        : )
            echo "${red}Option -${OPTARG} requires an argument.${reset}" >&2
            usage
            ;;
    esac
done

# Validate required arguments
if [ -z "$domain" ] || [ -z "$type" ]; then
    echo "${red}Domain and type are required.${reset}"
    usage
fi

# Sanitize domain format (prevent metacharacter injections)
if ! [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "${red}Invalid domain format: '$domain'. Only alphanumeric, dots, and hyphens are permitted.${reset}"
    exit 1
fi

type=$(echo "$type" | tr '[:lower:]' '[:upper:]')

case "$type" in
    API|WEB|ALL ) ;;
    * )
        echo "${red}Unknown scan type: $type${reset}"
        usage
        ;;
esac

if [ "$type" = "API" ] && [ -z "$api_collection" ]; then
    echo "${red}An API scan requires a collection file: -c <collection.json|collection.yaml>${reset}"
    usage
fi

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "${red}[!] This script must be run as root.${reset}"
    exit 1
fi

# Environment setup
format_newline
step "Setting Up Environment"
if ! mkdir -p "$results_dir" 2>/dev/null; then
    err "Could not create results directory: $results_dir"
    exit 1
fi
if [ ! -w "$results_dir" ]; then
    err "Results directory is not writable: $results_dir"
    err "Fix the ownership (e.g. chown -R \$SUDO_USER $results_dir) and re-run"
    exit 1
fi

format_newline
info "Domain Name: $domain"
ip_address=$(host "$domain" 2>/dev/null | awk '/has address/ { print $4 ; exit }')
if [ -z "$ip_address" ]; then
    err "Could not resolve $domain - check the domain name and your DNS"
    exit 1
fi
info "IP Address: $ip_address"

scheme=""
if [ "$type" = "WEB" ] || [ "$type" = "ALL" ]; then
    scheme=$(detect_scheme "$domain")
    if [ -z "$scheme" ]; then
        err "$domain answered on neither https nor http - aborting web scan"
        exit 1
    fi
    info "Scheme: $scheme://$domain"
fi

if [ "$type" = "ALL" ] && [ -z "$api_collection" ]; then
    warn "No -c collection supplied, skipping the API portion of the ALL scan"
    skipped_steps+=("API scan (no -c collection supplied)")
fi

scan_config() {
    case $type in
        "API" )
            ok "Running an API scan on $domain"
            api_scan
            ;;
        "WEB" )
            ok "Running a WEB scan on $domain"
            web_scan
            ;;
        "ALL" )
            ok "Running both API and WEB scans on $domain"
            if [ -n "$api_collection" ]; then
                scan_all
            else
                web_scan
            fi
            ;;
    esac
}

scan_config

# Generate summary report
generate_summary

# Dispatch completion email if configured
dispatch_email

# Fix results directory permissions for the non-root sudo caller
fix_permissions

format_newline
if [ ${#skipped_steps[@]} -gt 0 ]; then
    warn "Skipped ${#skipped_steps[@]} step(s):"
    for s in "${skipped_steps[@]}"; do echo "    - $s"; done
fi
if [ ${#failed_steps[@]} -gt 0 ]; then
    err "${#failed_steps[@]} step(s) failed:"
    for s in "${failed_steps[@]}"; do echo "    - $s"; done
fi

step "Script Done!"
step "Check your results in: $results_dir"

# Launch results web server / WebDAV browser if -s was supplied
launch_server

# non-zero exit when something actually broke, so this can be chained in CI
[ ${#failed_steps[@]} -eq 0 ]
