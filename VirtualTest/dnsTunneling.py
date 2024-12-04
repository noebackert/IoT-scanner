from scapy.all import DNS, DNSQR, IP, UDP, send
import sys

def generate_tunneling_traffic(target="8.8.8.8"):
    domain = "dGVzdERhdGEuZXhhbXBsZS5jb20="  # Base64-encoded string
    pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    send(pkt, count=10)  # Send 10 packets



def generate_legitimate_traffic(target="8.8.8.8"):
    domains = ["www.google.com", "www.facebook.com", "www.youtube.com"]
    for domain in domains:
        pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        send(pkt, count=5)  # Send 5 packets for each domain



if __name__ == "__main__":
    args = sys.argv
    target = None
    if "-h" in args:
        print("Usage: python dnsTunneling.py [-m message] [-t target]")
        sys.exit(0)
    if "-m" in args:
        message = args[args.index("-m") + 1]
    if "-t" in args:
        if len(args) > args.index("-t") + 1:
            target = args[args.index("-t") + 1]
        generate_tunneling_traffic(target)
    if "-l" in args:
        target = args[args.index("-l") + 1]
        generate_legitimate_traffic(target)
    else:
        print("Usage: python dnsTunneling.py [-m message] [-t target]")
        sys.exit(0)
