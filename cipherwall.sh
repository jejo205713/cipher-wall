# CipherWall This script will implement several preventive measures to make the cloud infrastructure more resilient against DDoS attacks.
#!/bin/bash

# Variables
SSH_PORT=22                    # Default SSH port
NEW_SSH_PORT=2200              # New SSH port for security
MAX_CONNECTIONS=100            # Max connections per IP
WEB_SERVER_PORT=80             # Web server port
LOG_FILE=/var/log/prevent.log  # Log file for security actions

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

# AUTHOR:JEJO.J & DEDSEC_TEAM
