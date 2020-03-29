#!/bin/bash

#Inputs argument as hostname or IP
#Automating routine enumeration tasks.
echo Initial Host Enumeration Script
echo by Cary Hooper @nopantrootdance
#TODO
#echo all open ports with nmap sV service detection
#can we extract hostname from nmap scan? 
#support for openSSL certificate parsing
#smb checks... 1) enumerate with enum4linux 2) check for anonymous read 2) check for anonymous write
#smtp checks - is login allowed? can we VRFY users?
#UDP nmap scan... at least top 5 UDP services
#tftp checks - any files available to download?  can we write files?
#snmp checks - 1) brute top 5-10 community strings... if found, do snmpwalk.
#dns checks (TCP and UDP) - zone transfer, name lookups to find hostname.

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
echo -e "\t[*] Beginning nmap scan of target."
nmap -p- -oA nmap/$target -Pn -T5 -sV -v0 $target > /dev/null 2>&1

#----------------------------------------------------------------------
#Check for http(s)
httpPorts=()
count=$(cat nmap/$target.nmap | egrep " http | ssl/http | https " | grep -v "incorrect results at " | wc -l)
if [ $count -ne 0 ]
then
	httpflag=1
	echo "[!] Detected HTTP/HTTPS"
	query=$(cat nmap/$target.nmap | egrep " http | ssl/http | https " | grep -v "incorrect results at ")
	while read -r line; do
		port=$(echo -n "$line" | cut -d '/' -f1)
		echo "[!] Port $port is a web service"
		httpPorts+=("$port")

	done <<< $(echo "$query")
else
	httpflag=0
	echo httpflag is $httpflag
fi

#Do http enumeration things.
#using ( ) subshell notation to suppress output
for port in ${httpPorts[@]}; do 
	#Nikto
	echo -e "\t[*] Starting nikto against port $port"
	( nikto -h http://$target:$port -o nikto.$target.$port.txt > /dev/null 2>&1 & )
	#Dirbuster
	echo -e "\t[*] Starting dirb against port $port"
	( dirb http://$target:$port -o dirb.$target.$port.txt > /dev/null 2>&1 & )
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
	#echo ftpflag is $ftpflag
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
echo -e "[*] Starting nmap NSE scan"
nmap -p- -A -oA nmap/$target-NSE -Pn -T5 -sV -v0 $target > /dev/null 2>&1

#Examine https certificate
#echo | openssl s_client -showcerts -servername 192.168.0.116 -connect 192.168.0.116:443 2>/dev/null | openssl x509 -inform pem -noout -text

echo -e '\nProgram Complete\n'

#Iterate over newline-separated variable
# 	while read -r line; do
# 		echo "... $line ..."
# 	done <<< "$query"

# #Iterate over array
# 		for i in ${httpPorts[@]}; do 
# 			echo $i;
# 		done