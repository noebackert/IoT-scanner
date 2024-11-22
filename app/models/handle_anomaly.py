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
def log_anomaly(anomaly_type:str, anomaly_number:int, id_victim:int, attacker_id:int=None):
    """
    Logs an anomaly to the database.
    
    Args:
        - anomaly_type: String, type of the anomaly.
        - anomaly_number: Integer, number of the anomaly.
        - id_victim: Integer, id of the victim.
        - attacker_id: Integer, id of the attacker.
    """
    if anomaly_type == "port_scan":
        anomaly_threat_level = 1
    elif anomaly_type == "dos":
        anomaly_threat_level = 2
    anomaly = Anomaly(
        id_victim = id_victim,
        attacker_id=attacker_id,
        anomaly_type=anomaly_type,
        threat_level=anomaly_threat_level,
        threat_label=labels[anomaly_threat_level],
        file_path=f"app/static/anomalies/{anomaly_type}/{anomaly_number}.pcap",
        date=datetime.now(pytz.timezone(LOCALISATION)),
    )
    db.session.add(anomaly)
    db.session.commit()
    return anomaly