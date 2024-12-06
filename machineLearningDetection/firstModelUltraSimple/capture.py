from scapy.all import sniff, wrpcap

# Number of packets to capture
PACKET_COUNT = 1000

print("Capturing network packets…")

# Capture packets
packets = sniff(count=PACKET_COUNT)

# Save captured packets to a file
wrpcap('network_traffic.pcap', packets)

print(f"Captured {PACKET_COUNT} packets and saved to 'network_traffic.pcap'")