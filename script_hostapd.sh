#!/bin/bash
# Prompt for SSID and Passphrase
read -p "Enter SSID: " ssid
read -p "Enter Passphrase: " passphrase
read -p "Access Point Wireless Interface (e.g., wlan1): " interface

# Step 1: Set up AP interface with a static IP
sudo ip addr add 192.168.10.1/24 dev $interface
sudo ip link set "$interface" up

# Step 2: Configure Network Interfaces
echo "Configuring network interfaces..."
cat <<EOF > /etc/network/interfaces
source-directory /etc/network/interfaces.d
auto lo
iface lo inet loopback

# Configure wlan0 for DHCP (for internet source)
allow-hotplug wlan0
iface wlan0 inet dhcp

# Configure $interface (AP interface) with static IP
allow-hotplug $interface
iface $interface inet static
    address 192.168.10.1
    netmask 255.255.255.0
EOF
systemctl enable networking

# Step 3: Install and Configure Hostapd
sudo apt install -y hostapd
echo "Creating hostapd configuration..."
sudo bash -c "cat > /etc/hostapd/hostapd.conf <<EOF
interface=$interface
driver=nl80211
ssid=$ssid
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$passphrase
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF"
sudo systemctl unmask hostapd
sudo systemctl enable hostapd

# Step 4: Install and Configure DNSMasq for DHCP
echo "Configuring dnsmasq..."
sudo apt-get install -y dnsmasq
cat <<EOF > /etc/dnsmasq.conf
interface=$interface
dhcp-range=192.168.10.50,192.168.10.150,12h
dhcp-option=3,192.168.10.1
dhcp-option=6,8.8.8.8,8.8.4.4
EOF
sudo systemctl enable dnsmasq

# Step 5: Enable IPv4 Forwarding
echo "Enabling IPv4 forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sudo sysctl -p

# Step 6: Set NAT and Firewall Rules
echo "Setting up iptables rules..."
mkdir -p /etc/iptables
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
iptables -A FORWARD -i wlan0 -o $interface -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $interface -o wlan0 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Install iptables-persistent for persistence
export DEBIAN_FRONTEND=noninteractive
apt-get install -y iptables-persistent
unset DEBIAN_FRONTEND

# Step 7: Enable netfilter-persistent and Restart Services
echo "Enabling netfilter-persistent and restarting services..."
systemctl enable netfilter-persistent
sudo systemctl restart hostapd
sudo systemctl restart dnsmasq

echo "Access Point setup completed. Interface $interface is now an AP with IP 192.168.10.1, while wlan0 uses DHCP for internet."
