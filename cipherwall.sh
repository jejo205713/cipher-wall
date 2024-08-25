# CipherWall This script will implement several preventive measures to make the cloud infrastructure more resilient against DDoS attacks.
#!/bin/bash

# Variables
SSH_PORT=22                    # Default SSH port
NEW_SSH_PORT=2200              # New SSH port for security
MAX_CONNECTIONS=100            # Max connections per IP
WEB_SERVER_PORT=80             # Web server port
LOG_FILE=/var/log/prevent.log  # Log file for security actions

# Function to harden SSH access
harden_ssh() {
    # Change the default SSH port
    sed -i "s/Port $SSH_PORT/Port $NEW_SSH_PORT/g" /etc/ssh/sshd_config
    service sshd restart
    echo "$(date): SSH port changed to $NEW_SSH_PORT." | tee -a $LOG_FILE

    # Limit SSH login attempts to prevent brute-force attacks
    iptables -A INPUT -p tcp --dport $NEW_SSH_PORT -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport $NEW_SSH_PORT -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
    echo "$(date): SSH brute-force protection enabled." | tee -a $LOG_FILE
}

# Function to limit connections per IP to prevent DDoS
limit_connections() {
    iptables -A INPUT -p tcp --syn --dport $WEB_SERVER_PORT -m connlimit --connlimit-above $MAX_CONNECTIONS -j REJECT --reject-with tcp-reset
    echo "$(date): Connection limit set to $MAX_CONNECTIONS per IP." | tee -a $LOG_FILE
}

# Function to enable basic firewall rules
enable_firewall() {
    # Allow traffic on necessary ports
    iptables -A INPUT -p tcp --dport $WEB_SERVER_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $NEW_SSH_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS port
    iptables -A INPUT -p icmp -j ACCEPT  # Allow ICMP (Ping)

    # Drop all other incoming traffic
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    echo "$(date): Basic firewall rules applied." | tee -a $LOG_FILE
}

# Function to enable rate limiting on incoming traffic
rate_limit() {
    iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT
    iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
    echo "$(date): Rate limiting applied." | tee -a $LOG_FILE
}

# Main execution
harden_ssh
limit_connections
enable_firewall
rate_limit

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
echo "$(date): iptables rules saved." | tee -a $LOG_FILE

#CREDITS:
AUTHOR:JEJO.J & DEDSEC_TEAM
