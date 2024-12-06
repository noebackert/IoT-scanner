from scapy.all import rdpcap
import pandas as pd

print("Extracting features from captured packets…")

# Read packets from the pcap file
packets = rdpcap('network_traffic.pcap')
data = []

for pkt in packets:
    if pkt.haslayer('IP'):
        data.append({
        'src_ip': pkt['IP'].src,
        'dst_ip': pkt['IP'].dst,
        'protocol': pkt['IP'].proto,
        'length': len(pkt)
        })

# Create DataFrame
df = pd.DataFrame(data)

# Label the data (simulate malicious traffic)
df['label'] = 0 # Normal traffic
df.loc[df.sample(frac=0.1).index, 'label'] = 1 # Simulate 10% malicious traffic

# Encode categorical variables
df['src_ip'] = df['src_ip'].astype('category').cat.codes
df['dst_ip'] = df['dst_ip'].astype('category').cat.codes

# Save to CSV
df.to_csv('network_data.csv', index=False)

print("Extracted features and saved to 'network_data.csv'")