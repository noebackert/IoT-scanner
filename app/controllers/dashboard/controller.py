from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required, current_user
from ...models.dashboard.forms import sliderGlobalDataRate
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
        'form': sliderGlobalDataRate(),
        'devices': [d for d in devices],
        'anomalies': [a for a in anomalies],
        'data_rate_global': [d for d in data_rates],
        'data_rate_chart_data': jsonify(data_rate_chart_data).json,  # Serialize JSON for JavaScript
        'data_rate_refresh': config["Data_rate"].get("Refresh_global_data_rate", 10),
        'data_rate_connected_devices_refresh': config["Data_rate"].get("Refresh_connected_devices", 10),
        }
    min_val, max_val = content['form'].get_slider_range()
    content['min'] = min_val
    content['max'] = max_val
    
    if content["form"].validate_on_submit():
        logger.info(f"Slider value: {content['form'].slider.data}")
        return render_template(url_for('blueprint.dashboard') + '.html', content=content, username = current_user.username)
    return render_template(url_for('blueprint.dashboard') + '.html', content=content, username = current_user.username)

 
@login_required
def get_data_rate():
    """
    Get the data rate of the devices.
    """
    montreal_tz = pytz.timezone(LOCALISATION)
    batch_size = int(request.args.get('batch', 1))

@login_required
def get_data_rate():
    """
    Get the data rate for one or multiple devices.
    """
    montreal_tz = pytz.timezone(LOCALISATION)
    batch_size = int(request.args.get('batch', 1))

    # Handle multiple devices
    if request.args.get('device_ids'):
        device_ids = request.args.get('device_ids').split(',')
        response = {}

        for device_id in device_ids:
            device = Device.query.filter_by(id=device_id).first()
            if not device:
                continue  # Skip invalid devices

            data_rates = DataRate.query.filter_by(device_id=device_id).order_by(DataRate.date.desc()).limit(10 * batch_size).all()
            mean_data_rate = device.average_data_rate
            labels = [dr.date.astimezone(montreal_tz).strftime('%H:%M:%S') for dr in data_rates]

            response[device_id] = {
                'labels': labels,
                'data': [dr.rate for dr in data_rates],
                'average': mean_data_rate
            }
        return jsonify(response)
    else:
        device_id = 1
        device = Device.query.filter_by(id=device_id).first()
        data_rates = DataRate.query.filter_by(device_id=device_id).order_by(DataRate.date.desc()).limit(10 * batch_size).all()
        mean_data_rate = device.average_data_rate
        labels = [dr.date.astimezone(montreal_tz).strftime('%H:%M:%S %m-%d-%y') for dr in data_rates]
        data_rates = [dr for dr in data_rates]
        data_rates_batches = [data_rates[i:i+batch_size] for i in range(0, len(data_rates), batch_size)]
        data_rates_mean = [sum([dr.rate for dr in data_rate_batch])/len(data_rate_batch) for data_rate_batch in data_rates_batches]
        labels_batches = [labels[i] for i in range(0, len(labels), batch_size)]
        if batch_size > 1:
            data_rate_chart_data = {
                'labels': labels_batches,
                'data': data_rates_mean,
                'average': mean_data_rate
            }
        else:
            data_rate_chart_data = {
                'labels': labels,
                'data': [dr.rate for dr in data_rates],
                'average': mean_data_rate
            }
        return jsonify(data_rate_chart_data)





@login_required
def get_anomalies():
    """
    Get the anomalies of the devices.
    """    
    anomalies = Anomaly.query.order_by(Anomaly.date.desc()).all()
    tz = pytz.timezone(LOCALISATION) 
    anomalies_json = [
        {
            'id': a.id,
            'anomaly_type': a.anomaly_type,
            'threat_level': a.threat_level,
            'date': a.date.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S')
        } for a in anomalies
    ]
    return jsonify(anomalies_json)