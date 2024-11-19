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

logger = setup_logging()

@login_required
def hotspot():
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
    logger.info(f"Content : {content}")
    if content['form'].validate_on_submit():
        devices = Device.query.all()
        content = perform_network_scan(content)
        content = update_content(content)
        render_template(url_for('blueprint.hotspot') + '.html', content=content, username = current_user.username)
    else:
        content = update_content(content)
        logger.info("Scan status is True")
    for device in content['devices']:
        if not single_ping_check(device):
            device.is_online = False
            device.avg_ping = 9999
            db.session.commit()
            logger.info(f"Device {device.ipv4} is offline")
    return render_template(url_for('blueprint.hotspot') + '.html', content=content, username = current_user.username)

    

def reverse_dns_lookup(ipv4):
    try:
        # Perform reverse DNS lookup to get the hostname or IPv6 address
        host = socket.gethostbyaddr(ipv4)
        return host[2]  # This returns a list of IPv6 addresses if available
    except (socket.herror, socket.gaierror):
        logger.warning(f"Could not perform reverse DNS lookup for IP: {ipv4}")
        return None



def perform_network_scan(content):
    """
    Perform a network scan to find devices connected to the hotspot & resend page when finished.
    """
    target_ip = "192.168.10.50-150"  # defined by the hotspot DHCP range
    with open("nmap_output.txt", "w") as output_file:
        subprocess.run(["nmap", "-sn","-PE", target_ip], stdout=output_file)
    logger.info(f"Running command: nmap -sn {target_ip}")
    
    # Perform a network scan to find devices connected to the hotspot
    with open("nmap_output.txt", "r") as file:
        lines = file.readlines()
        ipv4 = None
        ipv6 = None
        mac = None
        vendor = None

        for line in lines:
            logger.info(f"Nmap return: {line}")
            if "Nmap scan report for" in line:
                # If there is a valid IP address
                ipv4 = line.split(" ")[-1].strip()
            
            if "MAC Address:" in line:
                # Ensure that the MAC Address and Vendor are correctly parsed
                try:
                    mac = line.split(" ")[2].strip()
                    vendor = line.split("(")[1].split(")")[0].strip()  # Sometimes vendor info might be missing
                except IndexError:
                    mac = None
                    vendor = "Unknown"
                    # Handle case where the vendor might be missing or in an unexpected format
                    logger.warning(f"Could not parse MAC address or vendor for IP: {ipv4}")
                
                # Perform reverse DNS lookup to get IPv6 address
                ipv6 = reverse_dns_lookup(ipv4)

                # Append device info including IPv6 if found
                logger.info(f"Found device: {ipv4} {mac} {vendor} {ipv6 if ipv6 else 'No IPv6 found'}")

                # Check if device already exists in the database
                device = Device.query.filter_by(mac=mac).first()
                if not device:  # new device
                    new_device = Device(ipv4=ipv4, mac=mac, vendor=vendor, ipv6=ipv6)
                    db.session.add(new_device)
                    db.session.commit()
                    logger.info(f"Device {mac} added to the database")
                    # Monitor the device connection
                    thread = threading.Thread(target=monitor_ping_device, args=(new_device,))
                    thread.start()

                else: # device already exists
                    logger.info(f"Device {mac} already exists in the database")
                    # Check if IP address has changed
                    if not device.is_online:
                        device.is_online = True
                        thread = threading.Thread(target=monitor_ping_device, args=(device,))
                        thread.start()
                    if device.ipv4 != ipv4:
                        device.ipv4 = ipv4
                    if device.ipv6 != ipv6:
                        device.ipv6 = ipv6
                    db.session.commit()
                    logger.info(f"Device {mac} IP address updated to {ipv4} and IPv6 updated to {ipv6 if ipv6 else 'No IPv6'}")
    return content



@login_required
def edit_device():
    """
    Control the edit devices page.
    Login is required to view this page.
    """
    devices = Device.query.all()
    device_mac = request.args.get('device_id', default=None)
    logger.info(f"Device ID: {device_mac}")
    selected_device = Device.query.filter_by(mac=device_mac).first()
    logger.info(f"Selected device: {selected_device}")
    
    content = {
        "form": EditDeviceForm(),
        "selected_device": selected_device,
        "devices": [d for d in devices
        ],
    }
    logger.info(f"Form validation status: {content['form'].validate_on_submit()}")
    logger.info(f"Form errors: {content['form'].errors}")
    if content["form"].validate_on_submit():
        # Select the device to edit
        device = Device.query.filter_by(mac=content["form"].mac.data).first()
        logger.info(f"Form data: {content['form'].data}")
        if device:
            device.name = content["form"].name.data if content["form"].name.data else None
            device.vendor = content["form"].vendor.data if content["form"].vendor.data else device.vendor
            device.model = content["form"].model.data if content["form"].model.data else None
            device.version = content["form"].version.data if content["form"].version.data else None
            db.session.commit()
            flash("Device information updated successfully!", "success")
            content = update_content(content)
            
            return redirect(url_for('blueprint.hotspot'))
        else:
            flash("Device not found in the database", "danger")

    return render_template(url_for('blueprint.edit_device') +'.html', content=content, username = current_user.username)




@login_required
def delete_device():
    """
    Control the delete devices page.
    Login is required to view this page.
    """
    device_mac = request.args.get('device_id', default=None)
    logger.info(f"Device ID: {device_mac}")
    selected_device = Device.query.filter_by(mac=device_mac).first()
    logger.info(f"Selected device: {selected_device}")
    if selected_device:
        monitorToDelete = Monitoring.query.filter_by(device_id=selected_device.id).all()
        logger.info(f"Monitor to delete: {monitorToDelete}")
        for monitor in monitorToDelete:
            db.session.delete(monitor)
            db.session.commit()
            logger.info(f"Monitor deleted: {monitor}")
        captureToDelete = Capture.query.filter_by(device_id=selected_device.id).all()
        for capture in captureToDelete:
            db.session.delete(capture)
            db.session.commit()
            logger.info(f"Capture deleted: {capture}")
        db.session.delete(selected_device)
        db.session.commit()
        flash("Device deleted successfully!", "success")
    else:
        flash("Device not found in the database", "danger")
    return redirect(url_for('blueprint.hotspot'))

def single_ping_check(device:Device):
    """
    Check if the device is online by pinging it.
    """
    file_name=f'pings/ping_{device.id}.txt'
    with open(file_name, 'w') as output_file:
        response = subprocess.run(["ping", "-c", "1", device.ipv4], stdout=output_file)
    is_online = response.returncode == 0
    ping = get_ping_from_file(file_name)
    device.is_online = is_online
    new_ping = Monitoring(device_id=device.id, ip=device.ipv4, ping=ping, date=datetime.now())
    db.session.add(new_ping)
    update_avg_ping()
    db.session.commit()
    logger.info(f"Ping: Device {device.ipv4} is {'online' if is_online else 'offline'}")
    return is_online

def monitor_ping_device(device:Device):
    """Monitor the connection of a device by pinging it."""
    while True:
        is_online = single_ping_check(device)
        device.is_online = is_online
        db.session.commit()
        if not is_online:
            logger.info(f"Device {device.ipv4} is offline. Stopping monitoring")
            break
        time.sleep(5)  # Ping every 5 seconds
    return is_online


def get_ping_from_file(file:str):
    """
    Get the ping from the ping output file.
    """
    with open(file, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if "time=" in line:
                ping = float(line.split(" ")[6].split("=")[1])
                logger.info(f"Ping: {ping} ms")
                return ping
    return 9999