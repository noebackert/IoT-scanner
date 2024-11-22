from ..models.sql import Anomaly,db
from datetime import datetime
import pytz
import os
LOCALISATION = os.getenv("LOCALISATION", "America/Montreal")
labels = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical"
}
def log_anomaly(anomaly_type, anomaly_number):
    """
    Logs an anomaly to the database.
    
    Args:
        anomaly_type: String, type of the anomaly.
    """
    if anomaly_type == "port_scan":
        anomaly_threat_level = 1
    elif anomaly_type == "dos":
        anomaly_threat_level = 2
    anomaly = Anomaly(
        anomaly_type=anomaly_type,
        file_path=f"app/static/anomalies/{anomaly_type}/{anomaly_number}.pcap",
        date=datetime.now(pytz.timezone(LOCALISATION)),
        threat_level=anomaly_threat_level,
        threat_label=labels[anomaly_threat_level],
    )
    db.session.add(anomaly)
    db.session.commit()
    return anomaly