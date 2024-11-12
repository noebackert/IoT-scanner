# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Business logic for user profile
"""
from flask import Flask, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from ...models.hotspot.forms import HotspotForm
from ...models.sql import db, UserDB
from scapy.all import ARP, Ether, srp

@login_required
def hotspot():
    """
        Control the hotspot page.
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - redirect to login page
        """
    content = {'form': HotspotForm(),
               'devices': [],
               'logs': "Nul"
    }
    if content['form'].scan_status:
        content['logs'] = "performing scan..."
        devices = perform_network_scan()
        content['devices']  = devices
        content['logs'] = f"found {len(devices)} devices"

    return render_template(url_for('blueprint.hotspot')+'.html', content=content)


def perform_network_scan():
    """
    Perform a network scan to find devices connected to the hotspot.

    Returns:
        - List of devices found on the network.
    """
    # Define the network range to scan
    target_ip = "192.168.137.1/24"  # Adjust this to your network range
    # Create an ARP request packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Parse the responses to extract device information
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices