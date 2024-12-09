from flask import current_app
from app.models.sql import Device, Monitoring, Capture, db
import subprocess
from .models.logging_config import setup_logging
from sqlalchemy import cast, String
from sqlalchemy.dialects.postgresql import INET
import json
import pytz
import os

LOCALISATION = os.getenv('LOCALISATION', 'America/Montreal')
logger = setup_logging()


def load_config(path="config.json"):
    with open(path) as config_file:
        return json.load(config_file)

def save_config(config):
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=4)


def with_app_context(func):
    """A decorator to push the Flask app context to threaded functions."""
    def wrapper(*args, **kwargs):
        with current_app.app_context():
            return func(*args, **kwargs)
    return wrapper

def update_avg_ping():
    """Update the average ping of all devices."""
    devices = Device.query.all()  # Get all devices
    
    for device in devices:
        pings = Monitoring.query.filter_by(device_id=device.id) \
            .order_by(Monitoring.date.desc()) \
            .limit(5).all()  # Use .all() to fetch results as a list

        if pings:
            # Calculate the average ping
            avg_ping = sum(ping.ping for ping in pings) / len(pings)
            device.avg_ping = avg_ping  # Update the device's avg_ping
        
        else:
            device.avg_ping = 0  # No pings available, set to None or 0 if preferred
        
    # Commit all changes at once to minimize database overhead
    db.session.commit()
    return True

def update_content(content):
    """
    Update the content of the pages.
    """
    tz = pytz.timezone(LOCALISATION)
    logs = db.session.query(Capture, Device).join(Device).all()
    devices = Device.query.order_by(cast(Device.ipv4, INET)).all()
    content['devices'] = [d for d in devices]
    content['logs'] = [log for log in logs]
    for i in range(0, len(content['logs'])):
        # Convert the date to the local timezone
        content['logs'][i].Capture.date = content['logs'][i].Capture.date.astimezone(tz)
    content['selected_devices'] = [d for d in devices if d.selected]
    return content

def ping_check(device:Device):
    """
    Check if the device is online by pinging it.
    """
    with open('ping_output.txt', 'w') as output_file:
        response = subprocess.run(["ping", "-c", "1", device.ipv4], stdout=output_file)
    is_online = response.returncode == 0
    logger.info(f"Ping: Device {device.ipv4} is {'online' if is_online else 'offline'}")
    return is_online


def add_large_packet_threshold(device:Device, threshold:int=int(1e6)):
    jsonConfig = load_config()
    logger.info(f"Packet size threshold: {jsonConfig['IDS_settings']['DEVICES']}")
    for i, elt in enumerate(jsonConfig['IDS_settings']["DEVICES"]):
        if elt['device_id'] == device.id:
            jsonConfig['IDS_settings']["DEVICES"][i]["ipv4"] = device.ipv4
            jsonConfig['IDS_settings']["DEVICES"][i]["threshold"] = threshold
            break
    else:
        jsonConfig['IDS_settings']["DEVICES"].append({"device_id": device.id, "ipv4":device.ipv4, "threshold": threshold})
    save_config(jsonConfig)

def delete_large_packet_threshold(device:Device):
    jsonConfig = load_config()
    if device:
        for i, elt in enumerate(jsonConfig['IDS_settings']["DEVICES"]):
            if elt['device_id'] == device.id:
                jsonConfig['IDS_settings']["DEVICES"].remove(elt)
                break    
    save_config(jsonConfig)

def get_above_data_rate_threshold(device:Device=None, ipv4:str=None):
    jsonConfig = load_config()
    if device:
        for elt in jsonConfig['IDS_settings']["DEVICES"]:
            if elt['device_id'] == device.id:
                return elt['threshold']
    if ipv4:
        for elt in jsonConfig['IDS_settings']["DEVICES"]:
            if elt['ipv4'] == ipv4:
                return elt['threshold']
    return None

def add_need_internet(device:Device, need_internet:bool=True):
    jsonConfig = load_config()
    for i, elt in enumerate(jsonConfig['IDS_settings']["DEVICES"]):
        if elt['device_id'] == device.id:
            jsonConfig['IDS_settings']["DEVICES"][i]["need_internet"] = need_internet
            break
    else:
        return
    save_config(jsonConfig)

def get_need_internet(device:Device=None, ipv4:str=None):
    """Return True if a device is configured to need internet and False otherwise."""
    jsonConfig = load_config()
    if device:
        for elt in jsonConfig['IDS_settings']["DEVICES"]:
            if elt['device_id'] == device.id:
                return elt['need_internet']
    if ipv4:
        for elt in jsonConfig['IDS_settings']["DEVICES"]:
            if elt['ipv4'] == ipv4:
                return elt['need_internet']
    return True