#!/bin/bash
echo "Resetting Network Settings..."

# Restart NetworkManager
sudo systemctl restart NetworkManager

# Reset and disable UFW
sudo ufw reset
sudo ufw disable

# Release and renew IP
sudo dhclient -r
sudo dhclient

# Re-apply Netplan (if used)
sudo netplan apply

echo "Network settings reset. Try reconnecting now."
