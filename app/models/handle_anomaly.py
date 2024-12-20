from ..models.sql import Anomaly,db
from datetime import datetime
import pytz
import os
from ..utils import load_config

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
    
   
    config = load_config()
    anomaly_threat_levels = config["IDS_settings"]["ThreatLevels"]
    anomaly = Anomaly(
        id_victim = id_victim,
        attacker_id=attacker_id,
        anomaly_type=anomaly_type,
        threat_level=anomaly_threat_levels[anomaly_type],
        threat_label=labels[anomaly_threat_levels[anomaly_type]],
        file_path=f"app/static/anomalies/{anomaly_type}/{anomaly_number}.pcap",
        date=datetime.now(pytz.timezone(LOCALISATION)),
        read=False
    )
    db.session.add(anomaly)
    db.session.commit()
    return anomaly