import threading
import asyncio
import time
from flask import Flask, render_template, url_for, jsonify, redirect
from flask_login import login_required
from ...models.hotspot.forms import HotspotForm
from ...models.logging_config import setup_logging
import psutil
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

logger = setup_logging()

@login_required
def hotspot():
    """
    Control the hotspot page.
    Login is required to view this page.
    """
    devices = []
    content = {
        'form': HotspotForm(),
        'devices': devices,
    }
    
    popen_count = len([p for p in psutil.process_iter() if "nmap" in p.name()])
    logger.info(f"Number of nmap processes running: {popen_count}")
    logger.info(f"Devices: {content['devices']}")

    if content['form'].validate_on_submit():
        if not content["form"].scan_status:
            content["form"].scan_status = True
            # Start scanning in a background thread when the switch is toggled ON
            threading.Thread(target=start_scan, args=content ,daemon=True).start()  # Start in a separate thread
        else:
            content["form"].scan_status = False  # Stop the scan if the switch is turned off
    return render_template(url_for('blueprint.hotspot') + '.html', content=content)


def start_scan(content):
    """
    Start scanning the network every 5 seconds while SCAN_ACTIVE is True.
    """
    devices = asyncio.run(perform_network_scan())
    content['devices'] = devices
    logger.info("Scan updated")


async def perform_network_scan():
    """
    Perform a network scan to find devices connected to the hotspot.
    """
    try:
        target_ip = "192.168.10.50-150"
        process = await asyncio.create_subprocess_exec("nmap", "-sn", target_ip, "-oN", "nmap_output.txt", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        logger.info("Scan started function side")
        await process.communicate()
        logger.info("Scan done")

        devices = []
        with open("nmap_output.txt", "r") as file:
            lines = file.readlines()
            ip = None
            mac = None
            vendor = None

            for line in lines:
                if "Nmap scan report for" in line:
                    # If there is a valid IP address
                    ip = line.split(" ")[-1].strip()

                if "MAC Address:" in line:
                    # Ensure that the MAC Address and Vendor are correctly parsed
                    try:
                        mac = line.split(" ")[1].strip()
                        vendor = line.split(" ")[4].strip()  # Sometimes vendor info might be missing
                        devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
                    except IndexError:
                        # Handle case where the vendor might be missing or in an unexpected format
                        logger.warning(f"Could not parse MAC address or vendor for IP: {ip}")
                        devices.append({'ip': ip, 'mac': mac, 'vendor': 'Unknown'})
        logger.info(f"Found {len(devices)} devices")
        return devices

    except Exception as e:
        logger.error(f"Error during network scan: {e}")
        return []
