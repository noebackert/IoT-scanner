from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required
from ...models.capture.forms import CaptureTimeForm, CaptureNumberForm
from ...models.logging_config import setup_logging
from ...models.sql import Device, Monitoring, db
from datetime import datetime
from ...utils import update_avg_ping, update_content
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

    content = update_content(content)
    logger.info(f"Content : {content}")
    if content['timeCaptureForm'].validate_on_submit():
        logger.info(f"TimeCaptureForm : {content['timeCaptureForm'].timeSelector.data}")
        time = content['timeCaptureForm'].timeSelector.data
        logger.info(f"TimeCaptureForm : {time}")
        devices = Device.query.all()
        for device in devices:
            if device.is_online:
                logger.info(f"Device : {device}")
                wrpcap(f"app/static/capture/{device.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pcap", sniff(timeout=time, filter=f"host {device.ipv4}", iface=os.getenv('INTERFACE', 'wlan1')))
        flash(f"Capture done for {time} seconds", 'success')
        return redirect(url_for('blueprint.capture'))

    if content['numberCaptureForm'].validate_on_submit():
        logger.info(f"NumberCaptureForm : {content['numberCaptureForm'].numberSelector.data}")
        number = content['numberCaptureForm'].numberSelector.data
        logger.info(f"NumberCaptureForm : {number}")
        devices = Device.query.all()
        for device in devices:
            if device.is_online:
                logger.info(f"Device : {device}")
                wrpcap(f"app/static/capture/{device.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pcap", sniff(count=number, filter=f"host {device.ipv4}", iface=os.getenv('INTERFACE', 'wlan1')))
        flash(f"Capture done for {number} packets", 'success')
        return redirect(url_for('blueprint.capture'))
    return render_template(url_for('blueprint.capture') + '.html', content=content)
