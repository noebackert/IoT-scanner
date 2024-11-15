from flask import Flask, redirect, render_template, url_for, jsonify, flash, session
from flask_login import login_required
from ...models.hotspot.forms import HotspotForm
from ...models.logging_config import setup_logging
from scapy.all import ARP, Ether, srp
import subprocess

logger = setup_logging()
devices = []

@login_required
def hotspot():
    """
    Control the hotspot page.
    Login is required to view this page.
    """
    content = {
        'form': HotspotForm(),

    }
    # Check if scan is complete and set the message
    logger.info("Hotspot page accessed")
    if content['form'].validate_on_submit():
            content = perform_network_scan(content)
    else:
        logger.info("Scan status is True")
    return render_template(url_for('blueprint.hotspot') + '.html', content=content)

    

def perform_network_scan(content):
    """
    Perform a network scan to find devices connected to the hotspot & resend page when finished.
    """
    target_ip = "192.168.10.50-150"
    with open("nmap_output.txt", "w") as output_file:
        subprocess.run(["nmap", "-sn", target_ip], stdout=output_file)
    logger.info("Scan started function side")
    logger.info(f"running command : nmap -sn {target_ip}")
    devices = []
    # Perform a network scan to find devices connected to the hotspot
    with open("nmap_output.txt", "r") as file:
        lines = file.readlines()
        ip = None
        mac = None
        vendor = None

        for line in lines:
            logger.info(f"Nmap return: {line}")
            if "Nmap scan report for" in line:
                # If there is a valid IP address
                ip = line.split(" ")[-1].strip()
            
            if "MAC Address:" in line:
                # Ensure that the MAC Address and Vendor are correctly parsed
                try:
                    mac = line.split(" ")[2].strip()
                    vendor = line.split(" ")[3].strip()  # Sometimes vendor info might be missing
                    devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
                    logger.info(f"Found device: {ip} {mac} {vendor}")
                except IndexError:
                    # Handle case where the vendor might be missing or in an unexpected format
                    logger.warning(f"Could not parse MAC address or vendor for IP: {ip}")
                    devices.append({'ip': ip, 'mac': mac, 'vendor': 'Unknown'})
    logger.info(f"Found {len(devices)} devices")
    content["devices"] = devices
    return content