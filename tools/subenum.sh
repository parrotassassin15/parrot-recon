#!/usr/bin/env bash
#
# Passive subdomain enumeration across several keyless sources.
#
# usage: subenum.sh <domain> [output-file]
#
# Why this exists: sublist3r's engine list has rotted. Baidu/Yahoo/Ask return
# nothing, DNSdumpster crashes on a CSRF regex, VirusTotal blocks the requests,
# and because sublist3r wraps its write in "if subdomains:" it then exits 0
# having created no file at all. This queries sources that still answer and
# merges the results, so an individual dead source degrades the output instead
# of zeroing it.
#
# Sources: certspotter (CT), crt.sh (CT), hackertarget (DNS), rapiddns,
#          plus subfinder / sublist3r when they are installed.
#
# Exit codes: 0 = at least one source answered, 1 = every source failed.

set -o pipefail

domain=${1:-}
outfile=${2:-}

if [ -z "$domain" ]; then
    echo "usage: $0 <domain> [output-file]" >&2
    exit 1
fi

tmp=$(mktemp -d -t parrot-subenum.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

raw=$tmp/raw
: > "$raw"

sources_ok=0
sources_failed=0

note() { echo "[*] $*" >&2; }

# keeps only real hostnames under the target domain.
# the ANSI strip matters: sublist3r prints coloured output, and without it the
# escape codes end up glued to the name ("92mapi.github.com")
filter_domain() {
    sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
        | tr 'A-Z' 'a-z' \
        | sed 's/^\*\.//; s/^\.//; s/[[:space:],]*$//' \
        | grep -E "^([a-z0-9_-]+\.)*${domain//./\\.}$" \
        | grep -vE '^\*'
}

record() {
    local name=$1 count
    count=$(wc -l < "$tmp/hit")
    if [ "$count" -gt 0 ]; then
        sources_ok=$((sources_ok + 1))
        note "$name -> $count"
        cat "$tmp/hit" >> "$raw"
    else
        sources_failed=$((sources_failed + 1))
        note "$name -> nothing"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

src_certspotter() {
    curl -s -m 45 "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" \
        | grep -oE '"[a-zA-Z0-9_*.-]+"' | tr -d '"' | filter_domain | sort -u > "$tmp/hit"
    record certspotter
}

src_crtsh() {
    # crt.sh is frequently 502 under load, so give it one retry
    local body=$tmp/crtsh.json
    curl -s -m 45 "https://crt.sh/?q=%25.$domain&output=json" > "$body"
    if ! grep -q 'name_value' "$body" 2>/dev/null; then
        sleep 3
        curl -s -m 45 "https://crt.sh/?q=%25.$domain&output=json" > "$body"
    fi
    grep -oE '"name_value":"[^"]+"' "$body" 2>/dev/null \
        | sed 's/"name_value":"//; s/"$//' | tr '\\n' '\n' | sed 's/\\n/\n/g' \
        | filter_domain | sort -u > "$tmp/hit"
    record crt.sh
}

src_hackertarget() {
    curl -s -m 45 "https://api.hackertarget.com/hostsearch/?q=$domain" \
        | cut -d, -f1 | filter_domain | sort -u > "$tmp/hit"
    record hackertarget
}

src_rapiddns() {
    curl -s -m 45 -A 'Mozilla/5.0' "https://rapiddns.io/subdomain/$domain?full=1" \
        | grep -oE '[a-zA-Z0-9_.-]+\.'"${domain//./\\.}" | filter_domain | sort -u > "$tmp/hit"
    record rapiddns
}

src_subfinder() {
    have subfinder || return 0
    subfinder -silent -d "$domain" 2>/dev/null | filter_domain | sort -u > "$tmp/hit"
    record subfinder
}

src_sublist3r() {
    have sublist3r || return 0
    # sublist3r only writes its file when it found something, so read stdout too.
    # strip the colour codes BEFORE extracting names, otherwise the grep starts
    # matching inside the escape sequence and yields "92mapi.example.com"
    sublist3r -d "$domain" -o "$tmp/sublist3r.txt" 2>/dev/null \
        | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
        | grep -oE '[a-zA-Z0-9_.-]+\.'"${domain//./\\.}" > "$tmp/s3r-stdout" || true
    cat "$tmp/sublist3r.txt" "$tmp/s3r-stdout" 2>/dev/null \
        | filter_domain | sort -u > "$tmp/hit"
    record sublist3r
}

note "Enumerating subdomains for $domain"

src_certspotter
src_crtsh
src_hackertarget
src_rapiddns
src_subfinder
src_sublist3r

sort -u "$raw" > "$tmp/final"
total=$(wc -l < "$tmp/final")

if [ -n "$outfile" ]; then
    cp "$tmp/final" "$outfile"
fi
cat "$tmp/final"

note "$total unique subdomain(s) from $sources_ok source(s); $sources_failed source(s) returned nothing"

if [ "$sources_ok" -eq 0 ]; then
    note "Every source failed or was blocked - this is NOT a confirmed 'no subdomains' result"
    exit 1
fi
exit 0
