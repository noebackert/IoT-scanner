from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required
from ...models.capture.forms import CaptureTimeForm, CaptureNumberForm, selectForm, CapturePlayForm
from ...models.logging_config import setup_logging
from ...models.sql import Device, Capture, Monitoring, db
from datetime import datetime
from ...utils import update_avg_ping, update_content, with_app_context
from scapy.all import sniff, wrpcap, rdpcap, conf
from .sniffer import Sniffer
import os
import time

logger = setup_logging()
sniffer = None

@login_required
def capture():
    """
    Control the capture page.
    Login is required to view this page.
    """
    global sniffer
    devices = Device.query.all()
    joined_logs = db.session.query(Capture, Device).join(Device).all()
    content = {
        'timeCaptureForm': CaptureTimeForm(),
        'numberCaptureForm': CaptureNumberForm(),
        'selectForm': selectForm(),
        'playCaptureForm': CapturePlayForm(),
        'devices': [d for d in devices],
        'selected_devices': [d for d in devices if d.selected],
        'logs': joined_logs,
        'capture': "stop"
        }
    content = update_content(content)
    if content['selectForm'].validate_on_submit():
        if content['selectForm'].action.data == "select":
            selected_device = Device.query.filter_by(id=content['selectForm'].device.data).first()
            selected_device.selected = True
            content = update_content(content)
            db.session.commit()
            return render_template(url_for('blueprint.capture') + '.html', content=content)
        else:
            selected_device = Device.query.filter_by(id=content['selectForm'].device.data).first()
            selected_device.selected = False
            content = update_content(content)
            db.session.commit()
            return render_template(url_for('blueprint.capture') + '.html', content=content)
    
    if content['timeCaptureForm'].validate_on_submit():
        time = content['timeCaptureForm'].timeSelector.data
        # if no device is selected, capture all devices
        logger.info(f"Selected devices: {content['selected_devices']}")
        if content['selected_devices']:
            get_capture(time=time, list_device=content['selected_devices'])
            flash(f"Capture done for {time} seconds", 'success')
            return redirect(url_for('blueprint.capture'))
        else:
            get_capture(time=time)
            flash(f"Capture done for {time} seconds", 'success')
            return redirect(url_for('blueprint.capture'))
    if content['numberCaptureForm'].validate_on_submit():
        number = content['numberCaptureForm'].numberSelector.data
        if content['selected_devices']:
            get_capture(number=number, list_device=content['selected_devices'])
            flash(f"Capture done with {number} packets", 'success')
            return redirect(url_for('blueprint.capture'))
        else:
            get_capture(number=number)
            flash(f"Capture done with {number} packets", 'success')
            return redirect(url_for('blueprint.capture'))
    if content['playCaptureForm'].validate_on_submit():
        logger.info(f"Capture action: {content['playCaptureForm'].value.data}")
        if content['playCaptureForm'].value.data == "play":
            content['capture']="play"
            time=datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
            if content['selected_devices']:
                logger.info(f"Capture devices: {content['selected_devices']}")
                hosts_str="_".join([str(d.id) for d in content['selected_devices']])
            else:
                logger.info(f"Capture all devices")
                hosts_str="all"
            filename=f"app/static/capture/{hosts_str}_{time}.pcap"
            sniffer = Sniffer(interface=os.getenv('INTERFACE', 'wlan1'), filepath=filename)
            sniffer.start()
            logger.info("Capture started")
        if content['playCaptureForm'].value.data == "pause":
            content['capture']="pause"
            sniffer.pause()
            logger.info("Capture paused")
        if content['playCaptureForm'].value.data == "resume":
            content['capture']="play"
            sniffer.resume()
            logger.info("Capture resumed")
        if content['playCaptureForm'].value.data == "stop":
            content['capture']="stop"
            sniffer.stop()
            if content['selected_devices']:
                save_capture(content['selected_devices'][0].id, sniffer.filepath)
            else:
                save_capture(1, sniffer.filepath)
            content = update_content(content)
            logger.info("Capture stopped")   
        logger.info(f"Capture status: {content['capture']}")
        return render_template(url_for('blueprint.capture') + '.html', content=content)
    return render_template(url_for('blueprint.capture') + '.html', content=content)


@login_required
def log():
    """ Control the capture logs page. """
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
    selected_log = request.args.get('log_id')
    if selected_log:
        logger.info(f"Selected log: {selected_log}")
        log = Capture.query.filter_by(id=selected_log).first()
        logger.info(f"Capture file: {log.file_path}")
        logger.info(f"{os.getcwd()}")
        logger.info(f"Selected capture: {capture}")
        packets = rdpcap(log.file_path)


    timestamp_start = float(packets[0].time)
    timestamp_end = float(packets[-1].time)
    duration = timestamp_end - timestamp_start

    content = {
        'devices': [d for d in devices],
        'log': log,
        'packets' : packets,
        'duration': duration,
        'protocols': protocols,
        'ether_type': ether_type,
    }
    content = update_content(content)

    return render_template(url_for('blueprint.log') + '.html', content=content)


def get_capture(time:int=None, number:int=None, list_device:list[Device]=None)->bool:
    """
    Get a capture from a device.
    
    Args:
        - time: Integer, time to capture packets.
        - count: Integer, number of packets to capture.
        - device: list of devices to capture packets.
        
    Returns:
        - List of packets.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    interface = os.getenv('INTERFACE', 'wlan1')

    try:
        if list_device is not None:
            if len(list_device) > 0:
                filter_host = "host " + " or host ".join([d.ipv4 for d in list_device])
                device_ids = "_".join([str(d.id) for d in list_device])
                logger.info(f"Capture devices: {device_ids}")
                filepath = f"app/static/capture/{device_ids}_{timestamp}.pcap"
                logger.info(f"Capture file: {filepath}")
                for device in list_device:
                    if time:
                        packets = sniff(timeout=time, filter=filter_host, iface=interface)
                        logger.info(f"Capture device {device} for {time} seconds")
                        wrpcap(filepath, packets )
                        save_capture(device.id, filepath)
                    elif number:
                        packets = sniff(count=number, filter=filter_host, iface=interface)
                        logger.info(f"Capture device {device} with {number} packets")
                        wrpcap(filepath, packets)
                        save_capture(device.id, filepath)
                    return True
                else:   
                    logger.error(f"Device {device} is offline")
                    return False
        else:
            filepath = f"app/static/capture/all_{timestamp}.pcap"
            if time:
                logger.info(f"Capture all devices for {time} seconds")
                packets = sniff(timeout=time, iface=interface)
                wrpcap(filepath, packets )
                save_capture(1, filepath)
            elif number:
                packets = sniff(count=number, iface=interface)
                logger.info(f"Capture all devices with {number} packets")
                wrpcap(filepath, packets)
                save_capture(1, filepath)
            return True
    except Exception as e:
        logger.error(f"Error during capture: {e}")
        return False

def save_capture(device_id, file_path):
    """
    Save a capture in the database.
    
    Args:
        - device_id: Integer, id of the Device.
        - file_path: String, path to the Capture file.
    """
    capture = Capture(device_id=device_id, file_path=file_path, date=datetime.now())
    db.session.add(capture)
    db.session.commit()
    logger.info(f"Capture saved in the database: {capture}")