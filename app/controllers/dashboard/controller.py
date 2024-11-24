from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required, current_user
from ...models.hotspot.forms import HotspotForm, EditDeviceForm
from ...models.logging_config import setup_logging
from scapy.all import ARP, Ether, srp
from ...models.sql import Device, Monitoring, Capture, Anomaly, DataRate ,db
from ...utils import update_avg_ping, update_content, load_config
from ...models.sniffer import Sniffer
import os
from datetime import datetime
import pytz

LOCALISATION = os.getenv('LOCALISATION', 'America/Montreal')
interface = os.environ.get('INTERFACE', 'wlan1')
path_to_sniffer = "sniffer.pcap"
logger = setup_logging()
sniffer=Sniffer(interface, path_to_sniffer)


@login_required
def dashboard():
    """
    Control the hotspot page.
    Login is required to view this page.
    """
    devices = Device.query.order_by(Device.ipv4).all()
    anomalies = Anomaly.query.order_by(Anomaly.date.desc()).all()
    data_rates = DataRate.query.order_by(DataRate.date.desc()).all()
    average_data_rate = Device.query.filter_by(id=1).first().average_data_rate
    config = load_config()
    data_rate_chart_data = {
        'labels': [dr.date.strftime('%Y-%m-%d %H:%M:%S') for dr in data_rates],
        'data': [dr.rate for dr in data_rates],
        'average': average_data_rate,
    }
    content = {
        'form': HotspotForm(),
        'devices': [d for d in devices],
        'anomalies': [a for a in anomalies],
        'data_rate_global': [d for d in data_rates],
        'data_rate_chart_data': jsonify(data_rate_chart_data).json,  # Serialize JSON for JavaScript
        'data_rate_refresh': config["Data_rate"].get("Refresh_global_data_rate", 10)        }
    
    return render_template(url_for('blueprint.dashboard') + '.html', content=content, username = current_user.username)

 
@login_required
def get_data_rate():
    """
    Get the data rate of the devices.
    """
    mean_data_rate = Device.query.filter_by(id=1).first().average_data_rate
    data_rates = DataRate.query.order_by(DataRate.date.desc()).limit(10)
    montreal_tz = pytz.timezone(LOCALISATION)
    labels = [dr.date.astimezone(montreal_tz).strftime('%H:%M:%S') for dr in data_rates]
    data_rate_chart_data = {
        'labels': labels,
        'data': [dr.rate for dr in data_rates],
        'average': mean_data_rate
    }
    return jsonify(data_rate_chart_data)