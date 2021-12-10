#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
	echo -e "\n[*] You must be root to run the script"
	exit
fi

function ctrl_c(){
	tput cnorm
	echo -e "\n\n[*] Exiting...\n"
	exit
}

trap ctrl_c int
tput civis; echo -ne "\n\n[*] Installing requirements\n\n"
apt-get install ipmitool nmap python3 python3-pip -y
echo -ne "\n\n[*] Installing python3 requirements\n\n"
pip3 install shodan colorama python-nmap
echo -ne "\n\n[*] All requirements have been installed\n"; tput cnorm