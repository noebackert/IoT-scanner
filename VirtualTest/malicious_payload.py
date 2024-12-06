from scapy.all import IP, TCP, send

def send_test_packets():
    # Define the target IP and port (adjust these as needed)
    target_ip = "192.168.10.65"
    target_port = 12345

    # List of test payloads
    test_payloads = [
        "This is a harmless message.",
        "malware detected here!",  # Malicious payload
        "Another harmless message.",
        "exploit attempt in progress.",  # Malicious payload
    ]

    for payload in test_payloads:
        # Craft the packet
        packet = IP(dst=target_ip) / TCP(dport=target_port) / payload
        # Send the packet
        send(packet)
        print(f"Sent packet with payload: {payload}")

# Run the function
if __name__ == "__main__":
    send_test_packets()
