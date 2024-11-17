from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required
from ...models.capture.forms import CaptureTimeForm, CaptureNumberForm, selectForm
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
    content = {
        'timeCaptureForm': CaptureTimeForm(),
        'numberCaptureForm': CaptureNumberForm(),
        'selectForm': selectForm(),
        'devices': [d for d in devices],
        'selected_devices': [d for d in devices if d.selected]
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
        
    return render_template(url_for('blueprint.capture') + '.html', content=content)


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