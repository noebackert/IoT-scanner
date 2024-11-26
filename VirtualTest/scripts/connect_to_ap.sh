#!/bin/sh

# create a virtual interface
iw dev wlan1 interface add wlan1 type managed

# Configure the wireless interface
iwconfig eth0 essid AP key 123soleil

# Obtain an IP address from DHCP
dnsmasq --dhcp --interface eth0

# Ping the gateway (replace 192.168.10.1 with your actual gateway IP)
ping -c 5 192.168.10.1

# Optionally, ping another device on the network
ping -c 5 192.168.10.51

sleep 3600