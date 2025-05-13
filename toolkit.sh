#!/bin/bash

# Load functions from external file
source ./functions.sh

# ========== Main Menu Loop ==========
while true; do
    CHOICE=$(whiptail --title "Network Troubleshooting Toolkit" \
    --menu "Choose an option:" 25 78 16 \
    "1" "Quick Network Diagnostics (Recommended)" \
    "2" "Detailed Network Tools" \
    "3" "AppArmor Status" \
    "4" "Firewall Management (UFW)" \
    "5" "Static IP Setup" \
    "6" "Logs Management" \
    "0" "Exit" 3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ $exitstatus != 0 ]; then
        break
    fi

    case $CHOICE in
        1) quick_diagnostics ;;
        2)
            # Detailed Tool Menu
            TOOL=$(whiptail --title "Detailed Network Tools" \
            --menu "Select a tool to run:" 25 78 16 \
            "1" "Show Hostname and IP" \
            "2" "Show Default Gateway" \
            "3" "DNS Lookup (google.com)" \
            "4" "Ping a Host" \
            "5" "Traceroute a Host" \
            "6" "Show Disk Usage" \
            "7" "Show System Uptime" \
            "8" "Show Network Interfaces" \
            "9" "Internet Speed Test" \
            "10" "Port Scanner" \
            "11" "Show ARP Table" \
            "12" "Check Public IP" \
            "13" "WHOIS Lookup" \
            "0" "Back to Main Menu" 3>&1 1>&2 2>&3)

            case $TOOL in
                1) show_hostname_ip ;;
                2) show_default_gateway ;;
                3) dns_lookup ;;
                4) ping_host ;;
                5) traceroute_host ;;
                6) show_disk_usage ;;
                7) show_uptime ;;
                8) show_network_interfaces ;;
                9) speed_test ;;
                10) port_scan ;;
                11) show_arp_table ;;
                12) check_public_ip ;;
                13) whois_lookup ;;
                0) ;;
            esac
            ;;
        3) apparmor_status ;;
        4) ufw_management ;;
        5) static_ip_setup ;;
        6) logs_management ;;
        0) exit 0 ;;
    esac

done
