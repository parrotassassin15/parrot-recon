!/usr/bin/env bash
#
# Search-engine dorks a domain via lynx and collects the resulting URLs.
#
# usage: dork.sh <domain> [output-file]
#
# Fixes vs the original:
#   * the domain used to be read from $domain, which parrot-recon.sh never
#     exported, so every run dorked an empty string. It is positional now.
#   * Google now serves lynx a "your browser isn't supported" JS wall, so the
#     scrape returned zero URLs for every target. We query Mojeek (scraper
#     friendly) and DuckDuckGo's no-JS HTML endpoint instead.
#   * a rate-limited engine used to look identical to "no results found";
#     it is now reported as a throttle and the script exits non-zero.
#
# env: DORK_DELAY - seconds to wait between queries (default 4)

set -o pipefail

domain=${1:-$domain}
outfile=$2
delay=${DORK_DELAY:-4}

if [ -z "$domain" ]; then
    echo "usage: $0 <domain> [output-file]" >&2
    exit 1
fi

if ! command -v lynx >/dev/null 2>&1; then
    echo "[!] lynx is not installed - cannot run the dork scan" >&2
    exit 1
fi

# scratch space, so the repo does not collect root-owned gone.tmp/gtwo.tmp/urls
tmp=$(mktemp -d -t parrot-dork.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

urls=$tmp/urls
raw_all=$tmp/raw-urls
: > "$urls"
: > "$raw_all"

# engines that answered vs engines that blocked us, so the summary can tell
# "nothing indexed" apart from "we got throttled"
engines_ok=0
engines_blocked=0

urldecode() {
    local d=${1//+/ }
    printf '%b' "${d//%/\\x}"
}

fetch() {
    lynx -dump -nonumbers -connect_timeout=20 "$1" 2>/dev/null
}

# Mojeek prints result URLs inline; strip its own chrome and the ad redirector
query_mojeek() {
    local q=$1 raw=$tmp/mojeek.txt
    fetch "https://www.mojeek.com/search?q=$q" > "$raw"

    if [ ! -s "$raw" ]; then
        engines_blocked=$((engines_blocked + 1))
        return
    fi

    engines_ok=$((engines_ok + 1))
    grep -oE 'https?://[^ )"<]+' "$raw" \
        | grep -vE 'mojeek\.com|admarketplace\.net|ip2location|creativecommons\.org' \
        | sed 's/[.,]*$//' >> "$raw_all"
}

# DuckDuckGo wraps results as https://duckduckgo.com/l/?uddg=<percent-encoded>
query_ddg() {
    local q=$1 raw=$tmp/ddg.txt
    fetch "https://html.duckduckgo.com/html/?q=$q" > "$raw"

    # the block page is tiny and carries an error-lite support address
    if grep -qiE 'error-lite|error%20getting%20results|error getting results|anomaly|unusual traffic|too many requests' "$raw" \
       || { ! grep -q 'uddg=' "$raw" && ! grep -qi 'no results' "$raw"; }; then
        engines_blocked=$((engines_blocked + 1))
        return
    fi

    engines_ok=$((engines_ok + 1))
    grep -oE 'uddg=[^&]+' "$raw" | cut -d= -f2- | while read -r enc; do
        urldecode "$enc"
        echo
    done >> "$raw_all"
}

dork() {
    echo -e "[~] Targeting Domain ->  $domain"

    local encoded
    encoded=$(echo "$domain" | sed 's/ /%20/g')

    local queries=(
        "%22$encoded%22"
        "site%3A$encoded"
        "site%3A$encoded+inurl%3Aadmin+OR+inurl%3Alogin"
        "site%3A$encoded+ext%3Asql+OR+ext%3Alog+OR+ext%3Abak+OR+ext%3Aconf"
    )

    local q first=1
    for q in "${queries[@]}"; do
        # engines rate-limit bursts, which used to surface as a silent "0 urls"
        [ $first -eq 1 ] || sleep "$delay"
        first=0
        echo -e "[~] Fixed URL -> $domain"
        echo -e "[!] Trying Payload $(urldecode "${q//+/ }")"
        query_mojeek "$q"
        query_ddg "$q"
    done

    # normalise, drop the engines' own links, dedupe
    grep -E '^https?://' "$raw_all" \
        | sed -E 's#^(https?://[^/]+)/+$#\1#' \
        | grep -vE '^https?://(html\.|lite\.)?duckduckgo\.com' \
        | grep -vE '^https?://(www\.)?(google|mojeek|bing)\.com' \
        | sort -u > "$urls"

    local count
    count=$(wc -l < "$urls")
    echo "Extraction -> Extracted $count urls from $engines_ok engine response(s)."
    echo ""
    cat "$urls"

    if [ "$engines_ok" -eq 0 ]; then
        echo "[!] Every search engine blocked or failed this run ($engines_blocked block(s))."
        echo "[!] Results are NOT complete - re-run later or raise DORK_DELAY (currently ${delay}s)."
        return 1
    fi
    if [ "$engines_blocked" -gt 0 ]; then
        echo "[!] $engines_blocked engine response(s) were blocked - results may be partial."
    fi
    return 0
}

if [ -n "$outfile" ]; then
    dork | tee "$outfile"
    rc=${PIPESTATUS[0]}
    # keep the raw URL list next to the report for the other tools to consume
    cp "$urls" "$(dirname "$outfile")/$domain-dork-urls.txt" 2>/dev/null
    exit "$rc"
else
    dork
fi
