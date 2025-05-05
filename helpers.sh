#!/bin/bash

# Helper function to check if a directory exists
check_directory() {
    if [ ! -d "$1" ]; then
        echo "Error: Directory $1 does not exist!"
        return 1
    fi
    return 0
}

# Helper function to check if a file exists
check_file() {
    if [ ! -f "$1" ]; then
        echo "Error: File $1 does not exist!"
        return 1
    fi
    return 0
}

# Helper function to validate IP address format
validate_ip() {
    local IP=$1
    local stat=1
    if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local OIFS=$IFS
        IFS='.' 
        ip=($IP)
        IFS=$OIFS
        if [ ${#ip[@]} -eq 4 ]; then
            stat=0
        fi
    fi
    return $stat
}

# Helper function to validate if a port is numeric
validate_port() {
    if [[ ! $1 =~ ^[0-9]+$ ]] || [ $1 -lt 1 ] || [ $1 -gt 65535 ]; then
        echo "Error: Invalid port number. It should be between 1 and 65535."
        return 1
    fi
    return 0
}

# Helper function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 command not found. Please install it first."
        return 1
    fi
    return 0
}

# Helper function to prompt the user for confirmation (Yes/No)
confirm_action() {
    RESPONSE=$(whiptail --title "Confirmation" --yesno "$1" 10 60 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        return 0  # Yes
    else
        return 1  # No
    fi
}

# Helper function to prompt the user for input and return it
get_input() {
    RESPONSE=$(whiptail --inputbox "$1" 10 60 "$2" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        echo "$RESPONSE"
    else
        return 1
    fi
}

# Helper function to check if a service is running
check_service_status() {
    if systemctl is-active --quiet "$1"; then
        echo "$1 is running."
    else
        echo "$1 is not running."
    fi
}

# Helper function to check system resource usage
check_system_resources() {
    echo "System Resource Usage:"
    free -h
    echo "CPU Usage:"
    top -n 1 | grep "Cpu(s)"
    echo "Memory Usage:"
    top -n 1 | grep "Mem"
}

# Helper function to view log files
view_log_file() {
    if check_file "$1"; then
        tail -f "$1"
    fi
}

# Helper function to start or stop a service
manage_service() {
    ACTION=$1
    SERVICE=$2
    if [ "$ACTION" == "start" ]; then
        sudo systemctl start "$SERVICE"
        echo "$SERVICE started."
    elif [ "$ACTION" == "stop" ]; then
        sudo systemctl stop "$SERVICE"
        echo "$SERVICE stopped."
    else
        echo "Invalid action. Use 'start' or 'stop'."
        return 1
    fi
}
