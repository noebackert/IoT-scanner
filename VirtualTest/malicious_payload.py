from scapy.all import IP, TCP, send
import sys


def send_test_packets(target = "192.168.10.65", port=12345, message="malware !!"):
    # Define the target IP and port (adjust these as needed)
    target_ip = target
    target_port = port

    
    # Craft the packet
    packet = IP(dst=target_ip) / TCP(dport=target_port) / message
    # Send the packet
    send(packet)

# Run the function
if __name__ == "__main__":
    args = sys.argv
    target = None
    port = None
    message = None
    if "-h" in args:
        print("Usage: python malicious_payload.py [-t target ip] [-m message] <-p target port> ")
        sys.exit(0)
    if "-m" in args:
        message = args[args.index("-m") + 1]
    if "-p" in args:
        if len(args) > args.index("-p") + 1:
            port = int(args[args.index("-p") + 1])
    if "-t" in args:
        if len(args) > args.index("-t") + 1:
            target = args[args.index("-t") + 1]
        send_test_packets(target, port, message)
    else:
        print("Usage: python malicious_payload.py [-t target ip] [-m message] <-p target port> ")
        sys.exit(0)
