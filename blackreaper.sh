#black reaper scrip  which actively monitor network traffic to detect potential DDoS attacks and take action by blocking suspicious IP addresses
#!/bin/bash

# Variables
THRESHOLD=1000          # Threshold for requests per IP per minute
BLOCK_TIME=3600         # Time to block the IP in seconds (1 hour)
LOG_FILE=/var/log/ddos.log  # Log file to record blocked IPs

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

# Infinite loop to continuously scan for DDoS attacks
while true; do
    detect_ddos
    sleep 60  # Run the detection every minute
done
