from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required
from ...models.capture.forms import CaptureTimeForm, CaptureNumberForm
from ...models.logging_config import setup_logging
from ...models.sql import Device, Capture, Monitoring, db
from datetime import datetime
from ...utils import update_avg_ping, update_content, with_app_context
from scapy.all import sniff, wrpcap
import os

logger = setup_logging()

@login_required
def capture():
    """
    Control the capture page.
    Login is required to view this page.
    """
    devices = Device.query.all()
    selected_device_mac = request.args.get('device_id')
    logger.info(f"Selected device : {selected_device_mac}")
    if selected_device_mac:
        selected_device = Device.query.filter_by(mac=selected_device_mac).first()
    else:
        selected_device = None
    content = {
        'timeCaptureForm': CaptureTimeForm(),
        'numberCaptureForm': CaptureNumberForm(),
        'devices': [{'id': d.id,'name': d.name,'ipv4': d.ipv4,'ipv6': d.ipv6,'mac': d.mac,'vendor': d.vendor,'model': d.model,'version': d.version,'is_online': d.is_online} for d in devices],
        'selected_device': selected_device
        }
    logger.info(f"selected_device : {selected_device}")
    content = update_content(content)
    logger.info(f"Content : {content}")
    if content['timeCaptureForm'].validate_on_submit():
        logger.info(f"TimeCaptureForm : {content['timeCaptureForm'].timeSelector.data}")
        time = content['timeCaptureForm'].timeSelector.data
        logger.info(f"TimeCaptureForm : {time}")
        # if no device is selected, capture all devices
        if selected_device: 
            get_capture(time=time, device=selected_device)
            flash(f"Capture done for {time} seconds", 'success')
            return redirect(url_for('blueprint.capture'))
        else:
            get_capture(time=time)
            flash(f"Capture done for {time} seconds", 'success')
            return redirect(url_for('blueprint.capture'))
    if content['numberCaptureForm'].validate_on_submit():
        logger.info(f"NumberCaptureForm : {content['numberCaptureForm'].numberSelector.data}")
        number = content['numberCaptureForm'].numberSelector.data
        logger.info(f"NumberCaptureForm : {number}")
        if selected_device:
            get_capture(number=number, device=selected_device)
            flash(f"Capture done with {number} packets", 'success')
            return redirect(url_for('blueprint.capture'))
        else:
            get_capture(number=number)
            flash(f"Capture done with {number} packets", 'success')
            return redirect(url_for('blueprint.capture'))
        
    return render_template(url_for('blueprint.capture') + '.html', content=content)


def get_capture(time:int=None, number:int=None, device:Device=None)->bool:
    """
    Get a capture from a device.
    
    Args:
        - time: Integer, time to capture packets.
        - count: Integer, number of packets to capture.
        - device: Device, device to capture packets.
        
    Returns:
        - List of packets.
    """
    if device:
        logger.info("Device is selected")
        if device.is_online:
            if time:
                logger.info(f"Capture device {device} for {time} seconds")
                wrpcap(f"app/static/capture/{device.id}_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap", sniff(timeout=time, filter=f"host {device.ipv4}", iface=os.getenv('INTERFACE', 'wlan1')))
                save_capture(device.id, f"app/static/capture/{device.id}_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap")
                return True
            elif number:
                logger.info(f"Capture device {device} with {number} packets")
                wrpcap(f"app/static/capture/{device.id}_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap", sniff(count=number, filter=f"host {device.ipv4}", iface=os.getenv('INTERFACE', 'wlan1')))
                save_capture(device.id, f"app/static/capture/{device.id}_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap")
                return True
        else:   
            logger.error(f"Device {device} is offline")
            return False
    else:
        if time:
            logger.info(f"Capture all devices for {time} seconds")
            wrpcap(f"app/static/capture/all_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap", sniff(timeout=time, iface=os.getenv('INTERFACE', 'wlan1')))
            hotspot_device = Device.query.filter_by(id=1).first()
            save_capture(hotspot_device.id, f"app/static/capture/all_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap")
            return True
        elif number:
            logger.info(f"Capture all devices with {number} packets")
            wrpcap(f"app/static/capture/all_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap", sniff(count=number, iface=os.getenv('INTERFACE', 'wlan1')))
            hotspot_device = Device.query.filter_by(id=1).first()
            save_capture(hotspot_device.id, f"app/static/capture/all_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.pcap")
            return True
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