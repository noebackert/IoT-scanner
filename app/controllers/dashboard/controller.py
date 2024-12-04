from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required, current_user
from ...models.dashboard.forms import sliderGlobalDataRate
from ...models.logging_config import setup_logging
from scapy.all import ARP, Ether, srp, rdpcap
from ...models.sql import Device, Monitoring, Capture, Anomaly, DataRate ,db
from ...utils import update_avg_ping, update_content, load_config
from ...models.sniffer import Sniffer
from ...controllers.controller import admin_required
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
            'threat_label': a.threat_label,
            'file_path': a.file_path,
            'date': a.date.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S'),
            'read': a.read,
        } for a in anomalies
    ]
    return jsonify(anomalies_json)

@admin_required
def delete_anomaly():
    """
    Delete an anomaly.
    """
    anomaly_id = request.args.get('anomaly_id')
    
    if ',' in anomaly_id:
        try:
            anomaly_ids = anomaly_id.split(',')
            for id in anomaly_ids:
                anomaly = Anomaly.query.filter_by(id=id).first()
                if anomaly:
                    db.session.delete(anomaly)
                    os.remove(anomaly.file_path)
        except:
            redirect(url_for('blueprint.dashboard'))
    elif 'all' in anomaly_id:
        try:
            anomalies = Anomaly.query.all()
            logger.info(f"Anomalies : {anomalies}")
            for anomaly in anomalies:
                db.session.delete(anomaly)
                try:
                    os.remove(anomaly.file_path)
                except OSError as e:
                    logger.error(f"Failed to delete file {anomaly.file_path}: {e}")
            db.session.commit()
        except Exception as e:
            logger.error(f"Error while deleting all anomalies: {e}")
            return redirect(url_for('blueprint.dashboard'))
    else:
        anomaly = Anomaly.query.filter_by(id=anomaly_id).first()
        try:
            db.session.delete(anomaly)
            os.remove(anomaly.file_path)
        except:
            redirect(url_for('blueprint.dashboard'))
    db.session.commit()
    return redirect(url_for('blueprint.dashboard'))



def toggle_read():
    """
    Mark an anomaly as read.
    """
    anomaly_id = request.args.get('anomaly_id')
    anomaly = Anomaly.query.filter_by(id=anomaly_id).first()
    anomaly.read = not anomaly.read
    db.session.commit()
    return redirect(url_for('blueprint.dashboard'))



@login_required
def anomaly():
    """ Control the anomaly logs page. """
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP/QUIC",

    }
    ether_type = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8847: "MPLS unicast",
        0x8848: "MPLS multicast",
        0x8100: "VLAN",
        0x8843: "PPP",
        0x8844: "PPP Discovery",
        0x9000: "Proprietary Protocol",
    }   


    devices = Device.query.all()
    selected_anomaly = request.args.get('anomaly_id')
    if selected_anomaly:
        try:
            logger.info(f"Selected anomaly: {selected_anomaly}")
            anomaly = Anomaly.query.filter_by(id=selected_anomaly).first()
            logger.info(f"Capture file: {anomaly.file_path}")
            logger.info(f"{os.getcwd()}")
            packets = rdpcap(anomaly.file_path)
        except:
            logger.error(f"Error during reading capture: {anomaly.file_path}")
            flash(f"Error during reading capture, file probably didn't exist {anomaly.file_path}", 'error')
            # update database
            db.session.delete(anomaly)
            db.session.commit()
            return redirect(url_for('blueprint.dashboard'))
        for packet in packets:
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load  # Access raw payload data
                #print(f"Raw Data: {raw_data}")
                print(f"payload: {packet.payload}")


    timestamp_start = float(packets[0].time)
    timestamp_end = float(packets[-1].time)
    duration = timestamp_end - timestamp_start

    content = {
        'devices': [d for d in devices],
        'log': anomaly,
        'packets' : packets,
        'duration': duration,
        'protocols': protocols,
        'ether_type': ether_type,
    }
    content = update_content(content)
    return render_template(url_for('blueprint.anomaly') + '.html', content=content, username = current_user.username)
