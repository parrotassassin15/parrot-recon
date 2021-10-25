#!/bin/bash

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


# sets up enviornment variables and terminal colors 
red=`tput setaf 1`
green=`tput setaf 2`
white=`tput setaf 7`
working_dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
tools_dir=$working_dir/tools/

#makes sure the user is running as root 
if [ `whoami` != "root" ]
then
   echo "[!] This Script Needs To Be Run As Root User"
   exit 0
fi

# starts the install of parrot recon tools and prints status 
echo "$green[+] Installing Tools Required For Parrot-Recon$white"

echo "$red[+] installing Apt Packages For Parrot-Recon$white"
sudo apt install nmap hydra nikto amass dirsearch ffuf dirbuster sslyze sublist3r wpscan wafw00f
sudo apt install golang-go 
sudo apt install golang

echo "$red[+] Installing Golang Tools For Parrot-Recon$white"
go install -v github.com/lukasikic/subzy@latest
go mod tidy; go mod init main; go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

# do not fuck with this it works dont mess with it parrot i swear 
echo "$red[+] Cloning Git Repos For Parrot-Recon$white"
git clone https://github.com/Dionach/CMSmap $tools_dir/CMSmap
git clone https://github.com/mlcsec/headi   $tools_dir/headi
git clone https://github.com/BountyStrike/Injectus $tools_dir/Injectus
git clone https://github.com/chrispetrou/FDsploit  $tools_dir/FDsploit
git clone https://github.com/0xInfection/XSRFProbe $tools_dir/XSRFProbe
git clone https://github.com/ticarpi/jwt_tool.git  $tools_dir/jwt_tool


# functions to make sure the tools are in the right place for parrot recon 
echo "$red[+] Running Functions To Put Tools In The Right Directory$white"

cmsmap() {
    

}

cmsmap

headi() {



}

headi

injectus() {



}

injectus

fdsploit() {



}

fdsploit


xsrfprobe() {



}

xsrfprobe

jwt_tool() {



}

jwt_tool


echo "$green[+] Script Done!"
echo "$green[+] You are Ready To Use Parrot-Recon!"