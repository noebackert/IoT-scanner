from scapy.all import sniff
import pandas as pd
import joblib

# Load the trained model
model = joblib.load('ids_model.joblib')

print("Starting real-time intrusion detection…")

# Function to process each packet
def detect_intrusion(packet):
    if packet.haslayer('IP'):
        pkt_info = {
        'src_ip': packet['IP'].src,
        'dst_ip': packet['IP'].dst,
        'protocol': packet['IP'].proto,
        'length': len(packet)
        }
        pkt_df = pd.DataFrame([pkt_info])

        # Encode categorical variables
        pkt_df['src_ip'] = pkt_df['src_ip'].astype('category').cat.codes
        pkt_df['dst_ip'] = pkt_df['dst_ip'].astype('category').cat.codes

        # Features
        X_new = pkt_df[['src_ip', 'dst_ip', 'protocol', 'length']]

        # Predict
        prediction = model.predict(X_new)

        if prediction[0] == 1:
            print(f"🚨 {packet.summary()}")
        else:
            print(f"✅ {packet.summary()}")

# Start sniffing
sniff(prn=detect_intrusion, store=0)