#!/bin/bash

# Function for Quick Network Diagnostics
quick_diagnostics() {
    echo "Performing quick network diagnostics..." > /tmp/quick_diag.txt

    # Hostname and IP
    echo -e "\n--- Hostname & IP ---" >> /tmp/quick_diag.txt
    echo "Hostname: $(hostname)" >> /tmp/quick_diag.txt
    echo "Local IP : $(hostname -I)" >> /tmp/quick_diag.txt

    # Default Gateway
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    echo -e "\n--- Default Gateway ---" >> /tmp/quick_diag.txt
    echo "Gateway: $GATEWAY" >> /tmp/quick_diag.txt

    # Internet Connectivity
    echo -e "\n--- Internet Connectivity ---" >> /tmp/quick_diag.txt
    if ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
        echo "✔ Internet appears to be working (Ping to 8.8.8.8 successful)" >> /tmp/quick_diag.txt
    else
        echo "✘ Cannot reach 8.8.8.8 — possible internet issue" >> /tmp/quick_diag.txt
    fi

    # DNS Resolution
    echo -e "\n--- DNS Lookup (google.com) ---" >> /tmp/quick_diag.txt
    DIG=$(dig google.com +short 2>/dev/null)
    if [ -n "$DIG" ]; then
        echo "✔ DNS working: google.com resolves to $DIG" >> /tmp/quick_diag.txt
    else
        echo "✘ DNS resolution failed. Try checking /etc/resolv.conf or try another DNS." >> /tmp/quick_diag.txt
    fi

    # Public IP
    echo -e "\n--- Public IP ---" >> /tmp/quick_diag.txt
    PUBLIC_IP=$(curl -s https://api.ipify.org)
    if [ -n "$PUBLIC_IP" ]; then
        echo "Your public IP is: $PUBLIC_IP" >> /tmp/quick_diag.txt
    else
        echo "✘ Failed to fetch public IP. Possible DNS or internet issue." >> /tmp/quick_diag.txt
    fi

    # Speed Test (if tool is installed)
    echo -e "\n--- Speed Test ---" >> /tmp/quick_diag.txt
    if command -v speedtest-cli &>/dev/null; then
        speedtest-cli --simple >> /tmp/quick_diag.txt
    else
        echo "Speedtest not available. Install with: sudo apt install speedtest-cli" >> /tmp/quick_diag.txt
    fi

    # Suggestions
    echo -e "\n--- Suggestions ---" >> /tmp/quick_diag.txt
    if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        echo "- Check if cable/wifi is connected properly." >> /tmp/quick_diag.txt
        echo "- Reboot router or modem." >> /tmp/quick_diag.txt
        echo "- Use alternate DNS like 8.8.8.8 or 1.1.1.1." >> /tmp/quick_diag.txt
    elif [ -z "$DIG" ]; then
        echo "- DNS seems broken. Try editing /etc/resolv.conf and add nameserver 8.8.8.8" >> /tmp/quick_diag.txt
    else
        echo "- No major issues detected. If slow, check speed test results." >> /tmp/quick_diag.txt
    fi

    whiptail --title "Quick Network Diagnostics" --scrolltext --textbox /tmp/quick_diag.txt 25 80
}

# Function to show Hostname and IP Address
show_hostname_ip() {
    output="Hostname: $(hostname)\n"
    output+="IP Address: $(hostname -I | awk '{print $1}')"
    whiptail --title "Hostname and IP" --msgbox "$output" 10 60
}

# Function to show Default Gateway
show_default_gateway() {
    output="Default Gateway: $(ip route | grep default | awk '{print $3}')"
    whiptail --title "Default Gateway" --msgbox "$output" 10 60
}

# Function for DNS Lookup
dns_lookup() {
    IP=$(nslookup google.com | grep -E 'Address: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | head -n 1)
    whiptail --title "DNS Lookup Result" --msgbox "DNS Lookup for google.com (IPv4): $IP" 10 60
}

# Function for Ping a Host
ping_host() {
    HOST=$(whiptail --inputbox "Enter host to ping:" 10 60 "google.com" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        echo "Pinging $HOST..." > /tmp/ping_output.txt
        ping -c 4 "$HOST" >> /tmp/ping_output.txt 2>&1
        whiptail --title "Ping Result for $HOST" --scrolltext --textbox /tmp/ping_output.txt 25 80
    fi
}

# Function for Traceroute
traceroute_host() {
    HOST=$(whiptail --inputbox "Enter host to traceroute:" 10 60 "google.com" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        echo "Tracerouting to $HOST..." > /tmp/traceroute_output.txt
        traceroute "$HOST" >> /tmp/traceroute_output.txt 2>&1
        whiptail --title "Traceroute to $HOST" --scrolltext --textbox /tmp/traceroute_output.txt 25 80
    fi
}

# Function to show Disk Usage
show_disk_usage() {
    df -h > /tmp/disk_usage.txt
    whiptail --title "Disk Usage" --scrolltext --textbox /tmp/disk_usage.txt 25 80
}

# Function to show System Uptime
show_uptime() {
    result=$(uptime)
    whiptail --title "System Uptime" --msgbox "$result" 10 60
}

# Function to show Network Interfaces
show_network_interfaces() {
    ifconfig -a > /tmp/interfaces.txt
    whiptail --title "Network Interfaces" --scrolltext --textbox /tmp/interfaces.txt 25 80
}

# Function to perform Speed Test
speed_test() {
    if command -v speedtest-cli &>/dev/null; then
        result=$(speedtest-cli --simple 2>&1)

        if echo "$result" | grep -qE "Temporary failure in name resolution|403|Cannot retrieve"; then
            result="✘ Speedtest failed due to DNS or access issues.

Suggestions:
- Check your internet connection.
- Ensure DNS is properly configured (e.g., use 8.8.8.8).
- Try running: sudo systemctl restart NetworkManager
"
        elif ! echo "$result" | grep -q "Download"; then
            result="✘ Speedtest did not return expected results.

Suggestions:
- Ensure you're connected to the internet.
- Try running speedtest-cli manually in the terminal to debug.
"
        fi
    else
        result="Speedtest not available.

Install it using:
sudo apt update && sudo apt install speedtest-cli"
    fi

    whiptail --title "Speed Test Result" --scrolltext --msgbox "$result" 25 90
}



# Function for Port Scan
port_scan() {
    HOST=$(whiptail --inputbox "Enter host to scan for open ports:" 10 60 "localhost" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        nmap "$HOST" > /tmp/portscan_output.txt 2>&1
        whiptail --title "Port Scan for $HOST" --scrolltext --textbox /tmp/portscan_output.txt 25 80
    fi
}

# Function to show ARP Table
show_arp_table() {
    arp -a > /tmp/arp_table.txt
    whiptail --title "ARP Table" --scrolltext --textbox /tmp/arp_table.txt 20 80
}

# Function to check Public IP
check_public_ip() {
    ip=$(curl -s ifconfig.me)
    whiptail --title "Public IP Address" --msgbox "Public IP Address: $ip" 10 60
}

# Function for WHOIS Lookup
whois_lookup() {
    DOMAIN=$(whiptail --inputbox "Enter domain to perform WHOIS lookup:" 10 60 "google.com" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        whois "$DOMAIN" > /tmp/whois_output.txt 2>&1
        whiptail --title "WHOIS for $DOMAIN" --scrolltext --textbox /tmp/whois_output.txt 25 80
    fi
}

# Function to check AppArmor Status
apparmor_status() {
    sudo apparmor_status > /tmp/apparmor_output.txt 2>&1
    whiptail --title "AppArmor Status" --scrolltext --textbox /tmp/apparmor_output.txt 25 80
}

# Function for Firewall Management (UFW)
ufw_management() {
    ACTION=$(whiptail --title "Firewall Management (UFW)" \
    --menu "Select an action:" 20 70 10 \
    "1" "Enable UFW" \
    "2" "Disable UFW" \
    "3" "Allow a Port" \
    "4" "Deny a Port" \
    "5" "Show UFW Status" \
    "6" "Show UFW Rules" \
    "7" "Create a New Rule" \
    "8" "Delete a Rule" \
    "9" "Update a Rule" \
    "0" "Back to Main Menu" 3>&1 1>&2 2>&3)

    [ $? != 0 ] && return

    case $ACTION in
        1) sudo ufw enable
           whiptail --title "UFW Enabled" --msgbox "UFW has been enabled." 12 70 ;;
        2) sudo ufw disable
           whiptail --title "UFW Disabled" --msgbox "UFW has been disabled." 12 70 ;;
        3) PORT=$(whiptail --title "Allow Port" --inputbox "Enter port to allow:" 12 70 3>&1 1>&2 2>&3)
           [ ! -z "$PORT" ] && sudo ufw allow "$PORT"/tcp && \
               whiptail --title "Success" --msgbox "Port $PORT allowed successfully!" 12 70 ;;
        4) PORT=$(whiptail --title "Deny Port" --inputbox "Enter port to deny:" 12 70 3>&1 1>&2 2>&3)
           [ ! -z "$PORT" ] && sudo ufw deny "$PORT"/tcp && \
               whiptail --title "Success" --msgbox "Port $PORT denied successfully!" 12 70 ;;
        5) STATUS=$(sudo ufw status)
           whiptail --title "UFW Status" --msgbox "$STATUS" 20 70 ;;
        6) RULES=$(sudo ufw status verbose)
           whiptail --title "UFW Rules" --msgbox "$RULES" 30 100 ;;
        7) # Create Rule
           ACTION=$(whiptail --title "Create New Rule" --menu "Select the action:" 20 70 2 "1" "Allow" "2" "Deny" 3>&1 1>&2 2>&3) || return
           PROTOCOL=$(whiptail --title "Protocol" --menu "Select protocol:" 20 70 2 "1" "TCP" "2" "UDP" 3>&1 1>&2 2>&3) || return
           PORT=$(whiptail --title "Port" --inputbox "Enter port:" 12 70 3>&1 1>&2 2>&3) || return
           if [ "$ACTION" -eq 1 ]; then
               [ "$PROTOCOL" -eq 1 ] && sudo ufw allow "$PORT"/tcp
               [ "$PROTOCOL" -eq 2 ] && sudo ufw allow "$PORT"/udp
               whiptail --title "Rule Created" --msgbox "Rule added: $PORT" 12 70
           else
               [ "$PROTOCOL" -eq 1 ] && sudo ufw deny "$PORT"/tcp
               [ "$PROTOCOL" -eq 2 ] && sudo ufw deny "$PORT"/udp
               whiptail --title "Rule Created" --msgbox "Rule added: $PORT" 12 70
           fi ;;
               8) # Delete Rule
           RULE_LIST=$(sudo ufw status numbered)
           MENU_ITEMS=()
           while read -r line; do
               if [[ "$line" =~ ^\[([0-9]+)\]\ (.+) ]]; then
                   NUM="${BASH_REMATCH[1]}"
                   DESC="${BASH_REMATCH[2]}"
                   MENU_ITEMS+=("$NUM" "$DESC")
               fi
           done <<< "$RULE_LIST"

           RULE_NUM=$(whiptail --title "Delete Rule" --menu "Select a rule to delete:" 30 100 20 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || return
           echo "y" | sudo ufw delete "$RULE_NUM" && \
               whiptail --title "Success" --msgbox "Rule [$RULE_NUM] deleted successfully!" 12 70 ;;
           
        9) # Update Rule
           RULE_LIST=$(sudo ufw status numbered)
           MENU_ITEMS=()
           while read -r line; do
               if [[ "$line" =~ ^\[([0-9]+)\]\ (.+) ]]; then
                   NUM="${BASH_REMATCH[1]}"
                   DESC="${BASH_REMATCH[2]}"
                   MENU_ITEMS+=("$NUM" "$DESC")
               fi
           done <<< "$RULE_LIST"

           RULE_NUM=$(whiptail --title "Update Rule" --menu "Select a rule to update (it will be deleted):" 30 100 20 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || return
           echo "y" | sudo ufw delete "$RULE_NUM" || return

           ACTION=$(whiptail --title "New Action" --menu "Allow or Deny?" 20 70 2 "1" "Allow" "2" "Deny" 3>&1 1>&2 2>&3) || return
           PROTOCOL=$(whiptail --title "Protocol" --menu "Select protocol:" 20 70 2 "1" "TCP" "2" "UDP" 3>&1 1>&2 2>&3) || return
           PORT=$(whiptail --title "Port" --inputbox "Enter new port number:" 12 70 3>&1 1>&2 2>&3) || return

           if [ "$ACTION" -eq 1 ]; then
               [ "$PROTOCOL" -eq 1 ] && sudo ufw allow "$PORT"/tcp
               [ "$PROTOCOL" -eq 2 ] && sudo ufw allow "$PORT"/udp
               whiptail --title "Rule Updated" --msgbox "Rule updated: Allow $PORT" 12 70
           else
               [ "$PROTOCOL" -eq 1 ] && sudo ufw deny "$PORT"/tcp
               [ "$PROTOCOL" -eq 2 ] && sudo ufw deny "$PORT"/udp
               whiptail --title "Rule Updated" --msgbox "Rule updated: Deny $PORT" 12 70
           fi ;;

        0) return ;;
    esac
}



# Function for Static IP Setup
static_ip_setup() {
    INTERFACE=$(whiptail --inputbox "Enter network interface (e.g., eth0, wlan0):" 10 60 "eth0" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        IP_ADDRESS=$(whiptail --inputbox "Enter static IP address:" 10 60 "192.168.1.100" 3>&1 1>&2 2>&3)
        NETMASK=$(whiptail --inputbox "Enter netmask:" 10 60 "255.255.255.0" 3>&1 1>&2 2>&3)
        GATEWAY=$(whiptail --inputbox "Enter default gateway:" 10 60 "192.168.1.1" 3>&1 1>&2 2>&3)

        sudo bash -c "echo 'interface $INTERFACE' > /etc/network/interfaces.d/$INTERFACE"
        sudo bash -c "echo 'static ip_address=$IP_ADDRESS/24' >> /etc/network/interfaces.d/$INTERFACE"
        sudo bash -c "echo 'static routers=$GATEWAY' >> /etc/network/interfaces.d/$INTERFACE"
        sudo bash -c "echo 'static domain_name_servers=8.8.8.8 8.8.4.4' >> /etc/network/interfaces.d/$INTERFACE"

        whiptail --title "Static IP Setup" --msgbox "Static IP setup complete for $INTERFACE with IP $IP_ADDRESS." 12 60
        sudo systemctl restart networking
    fi
}

# Function for Logs Management
logs_management() {
    OPTION=$(whiptail --title "Logs Management" \
    --menu "Choose a log to manage:" 15 60 5 \
    "1" "Show Syslog" \
    "2" "Show Auth.log" \
    "3" "Clear Syslog" \
    "4" "Clear Auth.log" \
    "0" "Back" 3>&1 1>&2 2>&3)

    case $OPTION in
        1) tail -n 30 /var/log/syslog > /tmp/syslog.txt
           whiptail --title "Syslog" --scrolltext --textbox /tmp/syslog.txt 25 80 ;;
        2) tail -n 30 /var/log/auth.log > /tmp/authlog.txt
           whiptail --title "Auth Log" --scrolltext --textbox /tmp/authlog.txt 25 80 ;;
        3) sudo truncate -s 0 /var/log/syslog ;;
        4) sudo truncate -s 0 /var/log/auth.log ;;
        0) ;;
    esac
}
