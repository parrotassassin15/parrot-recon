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
case $1 in
   -d | --domain)
         domain=$2
         ;;
esac 
case $3 in
   -t | --type)
         type=$4
         ;;
esac
case $5 in
   -w | --wordlist)
         wordlist=$6
         ;;
esac


# usage screen 
usage() {
      $format_newline
      echo "$green Usage:$white ./parrot-recon.sh -d/--domain <domain> -t/--type <scan-type>"
      echo ""
      $format_newline
      echo "Scan Types:"
        echo "$red API$white - Enumerates an API Finds Endpoints + Finds Common Misconfigurations"
        echo "$red WEB$white - Enumerates Web Application + Fuzzes Application & Runs a Vulnerability Scan"
        echo "$red ALL$white - API Enumeration + Web Enumeration"
        exit 0
}

# outputs if user does not enter domain 
if [ $# -lt 6 ]
then 
   usage
fi 

# checking to make sure user is running script as sudo
if [ `whoami` != "root" ]
then
   echo "[!] This Script Needs To Be Run As Root User"
   exit 0
fi

# setting up directories for recon tool
$format_newline
echo "[+] Setting Up Enviornment"
if [ ! -d "$results_dir" ]
then
   mkdir $results_dir
fi

# prints out website information to look back to 
if [ $# -eq 6 ]
then 
   $format_newline
   echo "[*] Domain Name: $domain"
   echo "[*] IP Address:  $(host $domain | awk '/has address/ { print $4 ; exit }')"
fi


# printing out scan configurations 
scan_config() {
      if [[ "$type" == "API" ]];
      then
         $format_newline
         echo "$green[+] Running an API scan on $domain"
      elif [ "$type" == "WEB" ];
      then
         $format_newline
         echo "$green[+] Running a WEB scan on $domain"
      else
         echo "$red Running an unknown scan"
      fi
}

scan_config

$format_newline
echo "$red[!] Script is Broken Please Wait Til Offical Release"
exit 0 

# enumerating websites domain using the tools from install script
echo "$blue[+] Starting Website Enumeration"
go run $tools_dir/main.go -t http://$domain || go run $tools_dir/main.go -t https://$domain   
echo "$red[+] Starting URL DORK Scan$white"
bash $tools_dir/dork.sh $domain > $results_dir/$domain-dork.txt
echo "$green[+] URL DORK Scan Saved To: $results_dir/$domain-dork.txt"
exit 0
echo "$red[+] Starting Nmap TCP Scan$white"
nmap -sV -sC $domain -oA $results_dir/$domain-tcp-scan --open
echo "$green[+] Nmap TCP Scan Saved To: $results_dir/$domain-tcp-scan"

echo "$red[+] Starting Nmap UDP Scan$white"
#nmap -sV -sU $domain -oA $results_dir/$domain-udp-scan --open 
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

#echo "$red[+] Starting Server Enumeration$white"
# have not yet picked out a tool for this

#echo "$red[+] Starting Request Enumeration$white"
#ruby http-get-header.sh $domain > $results_dir/req.txt
#echo "$green[+] HTTP Request Saved To: $results_dir/req.txt"

echo "$red[+] Starting Domain and File Brute Force$white"
dirsearch -u $domain -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -o $results_dir/$domain-server-dirs.txt
echo "$green[+] Domain and File Brute Force Saved To: $results_dir/$domain-server-dirs.txt"

echo "$red[+] Starting CMS Enumeration$white"
cmsmap -F https://$domain -o $results_dir/cmsenum-$domain.txt || cmsmap -F http://$domain -o $results_dir/cmsenum-$domain.txt
echo "$green[+] CMS Enumeration Saved To: $results_dir/cmsenum-$domain.txt"

# needs to be replaced
#echo "$red[+] Starting S3 Bucket Enumeration$white"
#python -m $tools_dir/S3Scanner scan --buckets-file $results_dir/subdomains-$domain.txt > $results_dir/s3enumeration-$domain.txt 

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

# enumerating websites domain for owasp top ten with tools from install script 
echo "$blue[+] Starting OWASP Enumeration$white"

# if tool cannot output to results dir replace tool
#echo "$red[+] Starting Injection Enumeration$white"
#injectx.py -u https://$domain || injectx.py -u http://$domain 

echo "$red[+] Starting CORS Enumeration$white"
python3 $tools_dir/cors_scanner.py -u https://$domain -csv $results_dir/$domain-cors.csv || python3 $tools_dir/cors_scanner.py -u http://$domain -csv $results_dir/$domain-cors.csv
echo "$green[+] CORS Enumaration Results Saved To: $results_dir/$domain-cors.csv"

echo "$red[+] Starting HTTP HEADER INJECTION Enumeration$white"
headi -u https://$domain/ > $results_dir/headi-$domain.txt || headi -u http://$domain/ > $results_dir/headi-$domain.txt
echo "$green[+] HTTP HEADER INJECTION Results Saved To: $results_dir/headi-$domain.txt"

# need to find a replacement tool for graphql injection
#echo "$red[+] Starting GraphQL Injection Enumeration$white"
#need to work on a automation replacement
#python3 graphqlmap.py 

echo "$red[+] Starting Open Redirect Enumeration$white"
python3 $tools_dir/Injectus.py -u https://$domain -op > $results_dir/open-redirect-$domain.txt || python3 $tools_dir/Injectus.py -u http://$domain -op > $results_dir/open-redirect-$domain.txt
echo "$green[+] Open Redirect Results Saved To: $results_dir/open-redirect-$domain.txt"

echo "$red[+] Starting CRLF Enumeration$white"
python3 $tools_dir/Injectus.py -u https://$domain -c > $results_dir/crlf-$domain.txt || python3 $tools_dir/Injectus.py -u http://$domain -c > $results_dir/crlf-$domain.txt
echo "$green[+] CRLF Results Saved To: $results_dir/crlf-$domain.txt"

echo "$red[+] Starting XSS Enumeration$white"
python3 $tools_dir/xssi.py $domain -o $results_dir/xssi-$domain.txt 
echo "$green[+] XSS Results Saved To: $results_dir/xssi-$domain.txt"

echo "$red[+] Starting XSRF/CSRF Enumeration$white"
xsrfprobe -u $domain -o $results_dir/xsrf-csrf-$domain
echo "$green[+] XSRF/CSRF Results Saved To:  $results_dir/xsrf-csrf-$domain"

echo "$red[+] Starting SQLI Enumeration$white"
python3 $tools_dir/sqli.py $domain -o $results_dir/sqli-$domain.txt
echo "$green[+] SQLI Results Saved To: $results_dir/sqli-$domain.txt"

# i need to work on a more reliable JWT enumeration method
echo "$red[+] Starting JWT Enumeration$white"
read -p "ENTER A JWT TOKEN (If none press [ENTER]): " token 
python3 $tools_dir/jwt_tool.py $token > $results_dir/jwt-enumeration-$domain.txt

echo "$red[+] Starting Subdomain Takover Enumeration$white"
subzy -targets $results_dir/subdomains-$domain.txt > $results_dir/takeover-$domain.txt
echo "$green[+] Subdomain Takeover Results Saved To: $results_dir/takeover-$domain.txt"

echo "$red[+] Starting DIRECTORY TRAVERSAL Enumeration$white"
python3 $tools_dir/fdsploit.py -u https://$domain > $results_dir/directory-traversal-$domain.txt || python3 $tools_dir/fdsploit.py -u http://$domain > $results_dir/directory-traversal-$domain.txt
echo "$green[+] DIRECTORY TRAVERSAL Results Saved To: $results_dir/directory-traversal-$domain.txt"

# echo "$red[+] Starting XXE Enumeration$white"
# need to work on a fix for this 
# enum up top for a request 
#ruby $tools_dir/XXEinjector.rb --host=$domain r --output=$results_dir/xxe-injection-$domain.txt --phpfilter

echo "$red[+] Starting RFI/LFI Enumeration$white"
echo "$red[+] Skipping til the sytax is fixed"
#ffuf -c -w /usr/share/wordlists/dirb/common.txt -u  https:$domain/FUZZ -e .php,.html,.js,.asp,.sh -o $results_dir/$domain-ffuf.txt || ffuf -c -w /usr/share/wordlists/dirb/common.txt -u  http:$domain/FUZZ -e .php,.html,.js,.asp,.sh -o $results_dir/$domain-ffuf.txt
#echo "$green[+] RFI/LFI Results Saved To: $results_dir/$domain-ffuf.txt"

#echo "$red[+] Starting OS COMMAND INJECTION Enumeration$white"
#commix -u https://$domain --level 3 || commix -u http://$domain --level 3 
# i need to find a better tool for the automation job

echo "$red[+] Starting HTTP SMUGGLING Enumeration$white"
python3 $tools_dir/smuggle.py -u https://$domain > $results_dir/smuggle-$domain.txt || python3 $tools_dir/smuggle.py -u http://$domain > $results_dir/smuggle-$domain.txt
echo "$green[+] HTTP SMUGGLING Results Saved To: $results_dir/smuggle-$domain.txt"

echo "$red[+] Starting Protocal Brute Force$white"
bash $tools_dir/hydra.sh $domain $results_dir/$domain-tcp-scan.nmap
echo "$green[+] Valid Passwords Outputed To $results_dir/valid_passwords-$domain.txt"

echo "$red[+] Starting WebDav Server"
python3 webdav/webdav.py

echo "$red[+] Script Done!$white"
echo "$red[+] Check Your WebDAV For The Results!$white"