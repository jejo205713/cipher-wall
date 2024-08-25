#Blackreaper script 
#This script will continuously monitor network traffic to detect potential DDoS attacks and take action by blocking suspicious IP addresses.


#!/bin/bash

# Variables
THRESHOLD=1000          # Threshold for requests per IP per minute
BLOCK_TIME=3600         # Time to block the IP in seconds (1 hour)
LOG_FILE=/var/log/ddos.log  # Log file to record blocked IPs

# Function to reset and configure iptables using ipguard rules
configure_iptables() {
    iptables-save > /etc/iptables/current-firewall-backup-of-$(date +%F).log
    iptables -F       
    iptables -F INPUT 
    iptables -F OUTPUT
    iptables -F FORWARD
    iptables -F -t mangle
    iptables -F -t nat
    iptables -X
    iptables -Z

    iptables -P FORWARD  DROP
    iptables -P INPUT  DROP
    iptables -P OUTPUT ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT ! -i lo -d 127.0.0.1/8 -j DROP
    iptables -A INPUT -m state --state INVALID -j DROP

    # Add the ipguard rules
    iptables -N RouterDATA
    iptables -N FireWALLED
    iptables -N ACL-WEB
    iptables -N ACL-WEB-SECURE
    iptables -N BLOCKED-DATA
    iptables -N MAIL-ROUTE
    iptables -N AUDIT_DROP

    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j RouterDATA

    iptables -A RouterDATA -p tcp --dport http -j ACL-WEB
    iptables -A RouterDATA -p udp --sport 67:68 --dport 67:68 -j FireWALLED
    iptables -A RouterDATA -p udp --sport 53 --dport 53 -m limit --limit 10/minute -j LOG --log-prefix "Port 53 Possible Exploit Detected :"
    iptables -A RouterDATA -m limit --limit 10/minute -j LOG --log-prefix "Router Throttled:"
    iptables -A RouterDATA -p tcp -m multiport --dports smtp,smtps,imap,imaps,pop3 -j MAIL-ROUTE
    iptables -A RouterDATA -m state --state ESTABLISHED,RELATED -j FireWALLED
    iptables -A RouterDATA -j DROP
    iptables -A INPUT -j RouterDATA

    iptables -N SYN-FLOOD
    iptables -A SYN-FLOOD -m limit --limit 1/s --limit-burst 4 -j LOG --log-prefix "PUNK! YOUR SYN-FLOOD IS LOGGED  :"
    iptables -A SYN-FLOOD -j REJECT
    iptables -A INPUT -p tcp --syn -j SYN-FLOOD

    iptables -N AUDIT_DROP
    iptables -A AUDIT_DROP -j AUDIT --type drop
    iptables -A AUDIT_DROP -j DROP
    iptables -A INPUT -j AUDIT_DROP

    iptables -A FireWALLED -p tcp --dport 22 -j LED --led-trigger-id ssh --led-always-blink
    iptables -A FireWALLED -p tcp --dport 25 -j LED --led-trigger-id smtp --led-always-blink
    iptables -A FireWALLED -p tcp --dport 139 -j LED --led-trigger-id rpc

    iptables -A FireWALLED -p tcp --syn -m connlimit --connlimit-above 11 --connlimit-mask 24 -j REJECT
    iptables -A FireWALLED -p tcp --syn --dport 80 -m connlimit --connlimit-above 10 --connlimit-mask 24 -j REJECT
    iptables -A FireWALLED -p tcp --syn --dport 25 -m connlimit --connlimit-above 2 --connlimit-mask 24 -j REJECT
    iptables -A FireWALLED -p tcp --syn --dport 23 -m connlimit --connlimit-above 2 --connlimit-mask 24 -j REJECT
    iptables -A FireWALLED -p tcp --syn --dport 9400 -m connlimit --connlimit-above 3 --connlimit-mask 24 -j REJECT

    iptables -A INPUT -p tcp --dport http -j ACL-WEB
    iptables -A INPUT -p tcp --dport https -j ACL-WEB-SECURE
    iptables -A INPUT -p tcp -j BLOCKED-DATA

    iptables -A INPUT -j DROP

    wget -qO - http://infiltrated.net/blacklisted | awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}'
}

# Function to detect DDoS
detect_ddos() {
    # Monitor network traffic and count requests per IP
    netstat -an | grep ':80' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip
    do
        # If requests per IP exceed the threshold, block the IP
        if [ "$count" -gt "$THRESHOLD" ]; then
            echo "$(date): DDoS detected from $ip with $count requests. Blocking for $BLOCK_TIME seconds." | tee -a $LOG_FILE
            iptables -A INPUT -s $ip -j DROP
            echo "$(date): $ip blocked." | tee -a $LOG_FILE
            # Schedule to unblock the IP after BLOCK_TIME
            (sleep $BLOCK_TIME; iptables -D INPUT -s $ip -j DROP; echo "$(date): $ip unblocked." | tee -a $LOG_FILE) &
        fi
    done
}

# Main execution
configure_iptables  # Reset and configure iptables
while true; do
    detect_ddos
    sleep 60  # Run the detection every minute
done
#credits:
#AUTHOR: JEJO.J & DEDSEC_TEAM
