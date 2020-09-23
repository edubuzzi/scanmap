#!/bin/bash

BLUE='\033[1;34m'
BOLD='\033[1m'
COLORF='\033[0m'
GREEN='\033[1;32m'
ORANGE='\033[1;33m'
RED='\033[1;31m'

credits(){
echo
echo -e "${BOLD}===============================================${COLORF}"
echo -e "${BOLD}Script developed by:${COLORF} ${BLUE}Eduardo Buzzi${COLORF}"
echo -e "${BOLD}More scripts in:${COLORF} ${RED}https://github.com/edubuzzi${COLORF}"
echo -e "${BOLD}===============================================${COLORF}"
}

recognition(){
echo
RAN=$(shuf -i 1-9999 -n1)
read -p "Range IPs (ex: 192.168.1.0/24) => " RANGE
if [ ! -z "$RANGE" ]
then
nmap -sn "$RANGE" | grep "scan report" | cut -d "(" -f2 | cut -d ")" -f1 >> .IPSrecognition$RAN.txt
echo "Wordlist with active IPs saved in => .IPSrecognition$RAN.txt"
else
recognition
fi
principal
}

SYNprincipal(){
RANsynp=$(shuf -i 1-9999 -n1)
echo
read -p "Wordlist with IPs => " WL
IPS=$(wc -l $WL | cut -d ' ' -f1)
echo
echo "Scanning $IPS IPs..."
echo
for i in `seq 1 $IPS`
do
IP=$(cat $WL | head -n$i | tail -n1)
SYNSCAN=$(nmap -sS --open $SRC $IP | awk '{print $1,$2;}' | grep "tcp" >> .syn-$IP.txt)
RESULT=$(cat .syn-$IP.txt)
PORTS=$(cat .syn-$IP.txt | cut -d '/' -f1 | tr '\n' ' ' | tr ' ' ',' | rev | cut -c 2- | rev)
if [ ! -z "$RESULT" ]
then
echo "IP: $IP"
echo
echo "$RESULT"
echo "$IP" >> SYNscan-ports-$RANsynp.txt
echo "$PORTS" >> SYNscan-ports-$IP-result.txt
rm .syn-$IP.txt
echo
else
continue
fi
done
echo "Scan Finished Sucessfully"
echo "Wordlist with IPs who need Version Scan has been saved in => SYNscan-ports-$RANsynp.txt"
principal
}

ScanVERSION(){
RANv=$(shuf -i 1-9999 -n1)
echo
read -p "Wordlist with IPs => " WL
IPS=$(wc -l $WL | cut -d ' ' -f1)
for j in `seq 1 $IPS`
do
IP=$(cat $WL | head -n$j | tail -n1)
PORTS=$(cat SYNscan-ports-$IP-result.txt)
echo
echo "IP: $IP"
echo "PORT SERVICE VERSION"
nmap -v $SRC -sV -p $PORTS $IP | grep "open" | awk '{print $1,$3,$4}' | grep -v "Discovered"
rm SYNscan-ports-$IP-result.txt
done
rm SYNscan-ports-$RANsynp.txt
principal
}

principal(){
credits
echo
echo "0 => Recognition Scan"
echo "1 => SYN Scan (Principal Ports)"
echo "2 => SYN Scan (All Ports)"
echo "3 => TCP Scan (Principal Ports)"
echo "4 => TCP Scan (All Ports)"
echo "5 => Version Scan (only with Wordlist of previous scans)"
echo "6 => UDP Scan (Principal Ports)"
echo "7 => UDP Scan (All Ports)"
echo "8 => Exit"
echo
read -p "Your Choice => " CHOICE
echo
if [ "$CHOICE" = 8 ]
then
exit
fi
read -p "Source Port? (ex: 194, 443, 826) => " SRC
if [ ! -z "$SRC" ] && [ "$SRC" -ge 1 ] && [ "$SRC" -le 65535 ]
then
SRC="-g $SRC"
else
SRC=""
fi
case $CHOICE in
0) recognition ;;
1) SYNprincipal ;;
2) ;;
3) ;;
4) ;;
5) ScanVERSION ;;
6) ;;
7) ;;
*) principal ;;
esac
}
principal
