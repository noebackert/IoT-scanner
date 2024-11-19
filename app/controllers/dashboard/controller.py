from flask import Flask, redirect, render_template, url_for, jsonify, flash, request
from flask_login import login_required, current_user
from ...models.hotspot.forms import HotspotForm, EditDeviceForm
from ...models.logging_config import setup_logging
from scapy.all import ARP, Ether, srp
from ...models.sql import Device, Monitoring, Capture, db
import subprocess
import threading
import time
import socket
from datetime import datetime
from ...utils import update_avg_ping, update_content
from ...models.sniffer import Sniffer
import os
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
    # Get all devices from the database ordered by IP address
    devices = Device.query.order_by(Device.ipv4).all()
    content = {
        'form': HotspotForm(),
        'devices': [d for d in devices],
        }
    
    return render_template(url_for('blueprint.dashboard') + '.html', content=content, username = current_user.username)

 