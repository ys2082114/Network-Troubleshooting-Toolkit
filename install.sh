#!/bin/bash

# Install required dependencies
install_dependencies() {
    echo "Installing required dependencies..."

    # Update package list
    sudo apt-get update

    # Install necessary tools and libraries
    sudo apt-get install -y \
        curl \
        net-tools \
        nmap \
        dnsutils \
        whiptail \
        iputils-ping \
        traceroute \
        tcpdump \
        iproute2 \
        apparmor \
        bash-completion \
	net-tools \
	whois \
        tree

    if [ $? -eq 0 ]; then
        echo "Dependencies installed successfully."
    else
        echo "Error: Failed to install dependencies."
        exit 1
    fi
}

# Set up AppArmor profiles (basic example)
# Set up AppArmor profiles (basic example)
setup_apparmor() {
    echo "Setting up AppArmor profiles..."

    # Check if the profile exists
    if [ -f ./network-toolkit-profile ]; then
        sudo cp ./network-toolkit-profile /etc/apparmor.d/
        sudo apparmor_parser -r /etc/apparmor.d/network-toolkit-profile

        if [ $? -eq 0 ]; then
            echo "AppArmor profiles set up successfully."
        else
            echo "Error: Failed to set up AppArmor profiles."
            exit 1
        fi
    else
        echo "Error: AppArmor profile 'network-toolkit-profile' not found in current directory."
        exit 1
    fi
}


# Set executable permissions for toolkit scripts
set_permissions() {
    echo "Setting executable permissions for toolkit scripts..."

    # Grant execute permissions to toolkit scripts
    chmod +x ./*.sh

    if [ $? -eq 0 ]; then
        echo "Permissions set successfully."
    else
        echo "Error: Failed to set executable permissions."
        exit 1
    fi
}

# Main installation procedure
main_installation() {
    # Install dependencies
    install_dependencies

    # Set up AppArmor
    setup_apparmor

    # Set executable permissions
    set_permissions

    echo "Installation complete! The network troubleshooting toolkit is ready to use."
}

# Run the installation
main_installation
