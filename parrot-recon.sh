#!/usr/bin/env bash

# WARNING! This tool is incredibly invasive and will make a lot of noise on a network it
# is designed for bug bounties not pentests involving a blue team. please be careful when
# using this tool. Also DISCLAIMER: I WILL NOT BE HELD RESPONSIBLE FOR ANY ILLEGAL ACTIVITY
# YOU DECIDE TO DO WITH THIS TOOL. IT WAS MADE FOR ETHICAL PURPOSES. PLEASE BE CARFUL!!!

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

# defines enviornment variables and terminal colors
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

# every step that fails lands here so the run can finish and still report honestly
declare -a failed_steps=()
declare -a skipped_steps=()

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

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

# several tools exit 0 having written nothing at all - sublist3r only creates
# its output file when it actually found subdomains - so confirm the artifact
# exists before claiming we saved it
saved() {
    local msg=$1 file=$2
    if [ -s "$file" ]; then
        ok "$msg"
        return 0
    fi
    warn "No output written to $file (the tool reported success but produced nothing)"
    return 1
}

# sslyze exits non-zero whenever a scan command reports a problem (an expired
# cert, a refused cipher probe) even though the report itself is complete, so
# judge it by the report it produced rather than by its exit code
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
    echo "${green}Usage:${reset} $0 -d <domain> -t <scan-type> [-w <wordlist>] [-c <api collection>]"
    format_newline
    echo "Scan Types:"
    echo "${red}API${reset} - Enumerates an API and finds common misconfigurations (requires -c)"
    echo "${red}WEB${reset} - Enumerates a Web Application and runs a vulnerability scan"
    echo "${red}ALL${reset} - Performs both API and Web enumeration"
    format_newline
    echo "Options:"
    echo "  -d  target domain (required)"
    echo "  -t  scan type: API | WEB | ALL (required, case insensitive)"
    echo "  -w  wordlist for content discovery (optional, WEB/ALL)"
    echo "  -c  API collection file: .json (Postman) or .yaml/.yml (OpenAPI) - required for API"
    echo "  -h  show this help"
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

    # unique hostnames for the host-level scans, full URLs for the request-level checks
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
            # -o is a prefix; nikto appends ".<format>" to it
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
            # string compare: curl reports 000 on connection failure, which is not a number we can -eq on
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

# the go SQL error probe lives in tools/ with its own go.mod, so it has to be
# built from that directory or go cannot resolve the module
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

#    if require_tool nmap "Nmap UDP scan"; then
#        step "Starting Nmap UDP Scan"
#        run_step "Nmap UDP scan" nmap -sV -sU "$domain" -oA "$results_dir/$domain-udp-scan" --open
#        ok "Nmap UDP Scan Saved To: $results_dir/$domain-udp-scan.*"
#    fi

    if require_tool wafw00f "IDS/IPS detection"; then
        step "Starting IDS/IPS Detection"
        run_step "wafw00f" wafw00f "$target" -o "$results_dir/wafw00f-$domain.txt" \
            && saved "IDS/IPS Results Saved To: $results_dir/wafw00f-$domain.txt" "$results_dir/wafw00f-$domain.txt"
    fi

    if require_tool curl "Subdomain enumeration"; then
        step "Starting Subdomain Enumeration"
        # tools/subenum.sh aggregates certspotter, crt.sh, hackertarget,
        # rapiddns and (when installed) subfinder/sublist3r. sublist3r alone is
        # no longer sufficient: most of its engines are dead or blocking, and it
        # writes no file at all when it finds nothing.
        run_step "subdomain enumeration" \
            bash "$tools_dir/subenum.sh" "$domain" "$results_dir/subdomains-$domain.txt" \
            && saved "Subdomains Saved To: $results_dir/subdomains-$domain.txt" \
                     "$results_dir/subdomains-$domain.txt"
    fi

    if require_tool nikto "Nikto scan"; then
        step "Starting Nikto Scan"
        rm -f "$results_dir/nikto-$domain.txt"
        # nikto treats -o as a PREFIX and appends ".<format>", so passing
        # "...nikto-domain.txt" produced "nikto-domain.txt.txt". Give it the
        # bare prefix and name the format explicitly.
        run_step "Nikto" nikto -h "$domain" -Format txt -o "$results_dir/nikto-$domain" \
            && saved "Nikto Scan Saved To: $results_dir/nikto-$domain.txt" "$results_dir/nikto-$domain.txt"
    fi

    if require_tool cmsmap "CMS enumeration"; then
        step "Starting CMS Enumeration"
        rm -f "$results_dir/cmsenum-$domain.txt"
        # -s skips cert validation so a self-signed target does not kill the run.
        # -F (fullscan) is deliberately NOT used: cmsmap's own help describes it
        # as "False positives and slow!", and it was the step that stalled long
        # runs. Set CMSMAP_FULL=1 to opt back into it.
        cmsmap_args=(-s)
        [ "${CMSMAP_FULL:-0}" = "1" ] && cmsmap_args=(-F -s)
        run_step "cmsmap" cmsmap "${cmsmap_args[@]}" "$target" -o "$results_dir/cmsenum-$domain.txt" \
            && saved "CMS Enumeration Saved To: $results_dir/cmsenum-$domain.txt" "$results_dir/cmsenum-$domain.txt"
    fi

    if require_tool sslyze "SSL scans"; then
        step "Starting SSL Scans"
        # modern sslyze dropped --regular; a bare invocation already runs the full suite
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

    # headi is built by the install script; it may be on PATH, dropped in tools/,
    # or left as a binary inside its own cloned source directory
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

    # -w was accepted but never used before; wire it into content discovery
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
    # API first, then WEB - neither may exit, or the other never runs
    api_scan
    web_scan
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# Parse command-line options
while getopts ":d:t:w:c:h" opt; do
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
        h )
            usage
            ;;
        c )
            api_collection=${OPTARG}
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

# accept web / Web / WEB
type=$(echo "$type" | tr '[:lower:]' '[:upper:]')

case "$type" in
    API|WEB|ALL ) ;;
    * )
        echo "${red}Unknown scan type: $type${reset}"
        usage
        ;;
esac

# an API scan with no collection has nothing to scan - fail before doing any work
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
# a previous run under a different uid can leave this unwritable, which would
# silently turn every "Saved To:" line into a lie
if [ ! -w "$results_dir" ]; then
    err "Results directory is not writable: $results_dir"
    err "Fix the ownership (e.g. chown -R \$SUDO_USER $results_dir) and re-run"
    exit 1
fi

# Output domain information
format_newline
info "Domain Name: $domain"
ip_address=$(host "$domain" 2>/dev/null | awk '/has address/ { print $4 ; exit }')
if [ -z "$ip_address" ]; then
    err "Could not resolve $domain - check the domain name and your DNS"
    exit 1
fi
info "IP Address: $ip_address"

# resolve the scheme once so no step has to guess
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

# Scan configuration
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


#step "Sending Completion Email "
#python3 mailserver/sendemail.py

#step "Opening Web Server"
#python3 webdav/webserver.py

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
step "Check Your WebDAV For The Results! ($results_dir)"

# non-zero exit when something actually broke, so this can be chained in CI
[ ${#failed_steps[@]} -eq 0 ]
