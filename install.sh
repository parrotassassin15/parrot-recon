#!/bin/bash

# banner
cat << "EOF"                                         
    ____  ____ _______________  / /______   ________  _________  ____ 
   / __ \/ __ `/ ___/ ___/ __ \/ __/ ___/  / ___/ _ \/ ___/ __ \/ __ \
  / /_/ / /_/ / /  / /  / /_/ / /_(__  )  / /  /  __/ /__/ /_/ / / / /
 / .___/\__,_/_/  /_/   \____/\__/____/  /_/   \___/\___/\____/_/ /_/ 
/_/                                                                   
    _            __        ____         
   (_)___  _____/ /_____ _/ / /__  _____
  / / __ \/ ___/ __/ __ `/ / / _ \/ ___/
 / / / / (__  ) /_/ /_/ / / /  __/ /    
/_/_/ /_/____/\__/\__,_/_/_/\___/_/     
                                        
                                        

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
sudo apt install nmap hydra nikto amass dirsearch ffuf dirbuster sslyze sublist3r wpscan wafw00f -y 
sudo apt install golang-go -y  
sudo apt install golang -y
sudo apt install lynx -y 

echo "$red[+] Installing Golang Tools For Parrot-Recon$white"
go install -v github.com/lukasikic/subzy@latest
go mod tidy; go mod init main; go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
go get github.com/bndr/gotabulate
go get github.com/bndr/gotabulate


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
  cd $tools_dir/CMSmap
  sudo python3 setup.py install
}

cmsmap

headi() {
  cd $tools_dir/headi/
  go build main.go
  sudo cp main /bin/headi
}

headi

injectus() {
  cd $tools_dir/Injectus/
  pip3 install -r requirements.txt
  cp *.py $tools_dir
}

injectus

fdsploit() {
  cd $tools_dir/FDsploit
  cp fdploit.py ../
  pip3 install -r requirements.txt
}

fdsploit


xsrfprobe() {
  cd $tools_dir/XSRFProbe
  sudo python3 setup.py install
}

xsrfprobe

jwt_tool() {
  echo "$red[!] JWT is not gonna be installed"

}

jwt_tool


# read -p "Enter Password for webdav access" pass
# read -e 

# needs to be set up properly
echo "$red[+] Setting up webDAV portion"
sudo cp webdav/wsgidav.service /etc/systemd/system/wsgidav.service



echo "$green[+] Script Done!"
echo "$green[+] You are Ready To Use Parrot-Recon!"
