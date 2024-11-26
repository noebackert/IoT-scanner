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


def load_config():
    with open('config.json') as config_file:
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

    devices = Device.query.order_by(cast(Device.ipv4, INET)).all()
    content['devices'] = [d for d in devices]
    content['logs'] = db.session.query(Capture, Device).join(Device).all()
    for i in range(0, len(content['logs'])):
        content['logs'][i].Capture.date = content['logs'][i].Capture.date.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S')
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