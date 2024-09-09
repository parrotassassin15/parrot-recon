#!/bin/bash

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

# defines enviornment variables and terminal colors
red=`tput setaf 1`
white=`tput setaf 7`
green=`tput setaf 2`
blue=`tput setaf 4`
working_dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
results_dir=$working_dir/results
tools_dir=$working_dir/tools
format_newline='printf \n'


# argument parsing to decide what scan should be ran
format_newline() {
    printf "\n"
}

# Usage function
usage() {
    format_newline
    echo "${green}Usage:${white} $0 -d <domain> -t <scan-type> -w <wordlist>"
    format_newline
    echo "Scan Types:"
    echo "${red}API${white} - Enumerates an API and finds common misconfigurations"
    echo "${red}WEB${white} - Enumerates a Web Application and runs a vulnerability scan"
    echo "${red}ALL${white} - Performs both API and Web enumeration"
    exit 0
}

api_scan(){
    echo "[!] API Scanning Not set up yet"
}

scan_all(){
    api_scan
    web_scan
}

web_scan(){
    # enumerating websites domain using the tools from install script
    echo "$blue[+] Starting Website Enumeration"
    go run $tools_dir/main.go -t http://$domain || go run $tools_dir/main.go -t https://$domain   
    echo "$red[+] Starting URL DORK Scan$white"
    bash $tools_dir/dork.sh $domain > $results_dir/$domain-dork.txt
    echo "$green[+] URL DORK Scan Saved To: $results_dir/$domain-dork.txt"

    echo "$red[+] Starting Nmap TCP Scan$white"
    nmap -sV -sC $domain -oA $results_dir/$domain-tcp-scan --open
    echo "$green[+] Nmap TCP Scan Saved To: $results_dir/$domain-tcp-scan"

    echo "$red[+] Starting Nmap UDP Scan$white"
    nmap -sV -sU $domain -oA $results_dir/$domain-udp-scan --open 
    echo "$green[+] Nmap UDP Scan Saved To: $results_dir/$domain-udp-scan"

    echo "$red[+] Starting IDS/IPS Detection $white"
    wafw00f https://$domain -o $results_dir/wafw00f-$domain.txt || wafw00f http://$domain -o $results_dir/wafw00f-$domain.txt
    echo "$green[+] IPS/IPS Results Saved To: $results_dir/wafw00f-$domain.txt"

    echo "$red[+] Starting Subdomain Enumeration$white"
    sublist3r -d $domain -o $results_dir/subdomains-$domain.txt 
    echo "$green[+] Subdomains Saved To: $results_dir/subdomains-$domain.txt"

    echo "$red[+] Starting Nikto Scan$white"
    nikto -h $domain -o $results_dir/nikto-$domain.txt
    echo "$green[+] Nikto Scan Saved To: $results_dir/nikto-$domain.txt"

    echo "$red[+] Starting CMS Enumeration$white"
    cmsmap -F https://$domain -o $results_dir/cmsenum-$domain.txt || cmsmap -F http://$domain -o $results_dir/cmsenum-$domain.txt
    echo "$green[+] CMS Enumeration Saved To: $results_dir/cmsenum-$domain.txt"

    echo "$red[+] Starting SSL Scans$white"
    sslyze --regular $domain > $results_dir/$domain-sslyze-regular.txt
    echo "$green[+] Regular SSL Scan Saved To: $results_dir/$domain-sslyze-regular.txt"
    sslyze --heartbleed $domain > $results_dir/$domain-sslyze-heartbleed.txt
    echo "$green[+] HeartBleed Scan Saved To: $results_dir/$domain-sslyze-heartbleed.txt"
    sslyze --robot $domain > $results_dir/$domain-sslyze-robot.txt
    echo "$green[+] Robot Scan Saved To: $results_dir/$domain-sslyze-robot.txt"

    echo "$red[+] Starting Nuclei Scans$white"
    nuclei -u $domain -o $results_dir/nuclei-$domain.txt
    echo "$green[+] Neclei Scans Saved To: $results_dir/nuclei-$domain.txt"

    echo "$red[+] Starting Request Enumeration$white"
    ruby http-get-header.sh $domain > $results_dir/req.txt
    echo "$green[+] HTTP Request Saved To: $results_dir/req.txt"

    echo "$red[+] Starting CORS Enumeration$white"
    python3 $tools_dir/cors_scanner.py -u https://$domain -csv $results_dir/$domain-cors.csv || python3 $tools_dir/cors_scanner.py -u http://$domain -csv $results_dir/$domain-cors.csv
    echo "$green[+] CORS Enumaration Results Saved To: $results_dir/$domain-cors.csv"

    echo "$red[+] Starting HTTP HEADER INJECTION Enumeration$white"
    headi -u https://$domain/ > $results_dir/headi-$domain.txt || headi -u http://$domain/ > $results_dir/headi-$domain.txt
    echo "$green[+] HTTP HEADER INJECTION Results Saved To: $results_dir/headi-$domain.txt"
}

# Parse command-line options
while getopts ":d:t:w:h" opt; do
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

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "${red}[!] This script must be run as root.${reset}"
    exit 1
fi

# Environment setup
format_newline
echo "[+] Setting Up Environment"
mkdir -p "$results_dir"

# Output domain information
format_newline
echo "[*] Domain Name: $domain"
ip_address=$(host $domain | awk '/has address/ { print $4 ; exit }')
echo "[*] IP Address: $ip_address"

# Scan configuration
scan_config() {
    case $type in
        "API" )
            echo "${green}[+] Running an API scan on $domain${reset}"
            ;;
        "WEB" )
            echo "${green}[+] Running a WEB scan on $domain${reset}"
            web_scan
            ;;
        "ALL" )
            echo "${green}[+] Running both API and WEB scans on $domain${reset}"
            ;;
        * )
            echo "${red}Unknown scan type: $type${reset}"
            usage
            ;;
    esac
}

scan_config


echo "$red[+] Sending Completion Email "
python3 mailserver/sendemail.py

echo "$red[+] Opening Web Server"
python3 webdav/webserver.py

echo "$red[+] Script Done!$white"
echo "$red[+] Check Your WebDAV For The Results!$white"
