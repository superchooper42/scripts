#!/bin/bash

#Inputs argument as hostname or IP
#Automating routine enumeration tasks.
echo Initial Host enumeration script
echo by Cary Hooper @nopantrootdance

if [ $# != 1 ]
then
	echo "usage: ./enum.sh <IP or hostname>"
	exit
fi
target=$1
#Make output directory if it doesn't exist.
#Todo - more graceful check of whether the dir exists.
mkdir nmap > /dev/null 2>&1
#Do the nmap scan
nmap -p- -oA nmap/$target -Pn -T5 -sV -v0 $target > /dev/null 2>&1

#----------------------------------------------------------------------
#Check for http(s)
httpPorts=()
count=$(cat nmap/$target.nmap | egrep " http | https " | wc -l)
if [ $count -ne 0 ]
then
	httpflag=1
	echo "[!] Detected HTTP/HTTPS"
	query=$(cat nmap/$target.nmap | egrep " http | https " )
	while read -r line; do
		port=$(echo -n "$line" | cut -d '/' -f1)
		echo "[!] Port $port is a web service"
		httpPorts+=("$port")

	done <<< "$query"
else
	httpflag=0
	echo httpflag is $httpflag
fi

#Do http enumeration things.
#using ( ) subshell notation to suppress output
for port in ${httpPorts[@]}; do 
	#Nikto
	echo "[*] Starting nikto against port $port"
	( nikto -h http://$target:$port -o nikto.$port.txt > /dev/null 2>&1 & )
	#Dirbuster
	echo "[*] Starting dirb against port $port"
	( dirb http://$target:$port -o dirb.$port.txt > /dev/null 2>&1 & )
done
#----------------------------------------------------------------------
#Check for ftp
ftpPorts=()
count=$(cat nmap/$target.nmap | egrep " ftp " | wc -l)
if [ $count -ne 0 ]
then
	ftpflag=1
	echo "[!] Detected FTP"
	query=$(cat nmap/$target.nmap | egrep " ftp " )
	while read -r line; do
		port=$(echo -n "$line" | cut -d '/' -f1)
		echo "[!] Port $port is hosting an ftp service"
		httpPorts+=("$port")

	done <<< "$query"
else
	ftpflag=0
	echo ftpflag is $ftpflag
fi
#Do ftp enumeration things
#Test for anonymous logon and anonymous write
echo h00p > ftptest.txt
for port in ${ftpPorts[@]}; do
	#Anonymous ftp login
	if [[ $(echo -e "USER anonymous\r\nPASS anonymous\r\n" | nc -nv $target $port | grep "230") =~ ^230.*$ ]]
	then 
		echo "[*] Anonymous login allowed on port $port"
	fi
	if [[ $(echo -e "USER anonymous\r\nPASS anonymous\r\nSTOR ftptest.txt\r\n\cc" | nc -nv $target $port | grep "150") =~ ^150.*$ ]]
	then 
		echo "[*] Anonymous write allowed on port $port"
	fi
	echo -e "USER anonymous\r\nPASS anonymous\r\nSTOR ftptest.txt\r\n\cc" | nc -nv $target $port | grep "150"
	ps -aef | grep "nc -nv 192" | grep -v grep | awk '{print $2}' | xargs kill
done #Save output of this into file.
rm ftptest.txt
#----------------------------------------------------------------------




echo "\n\n Program Complete \n\n"

#Iterate over newline-separated variable
	while read -r line; do
		echo "... $line ..."
	done <<< "$query"

#Iterate over array
		for i in ${httpPorts[@]}; do 
			echo $i;
		done