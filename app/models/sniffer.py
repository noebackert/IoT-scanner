from collections.abc import Callable
from typing import Any, Iterable, Mapping
from scapy.all import sniff, wrpcap, IP, TCP
from threading import Thread, Event
from collections import deque
from .logging_config import setup_logging
from .handle_anomaly import log_anomaly
from time import time, sleep
from .sql import Device, DataRate, db
from datetime import datetime
import pytz
import os
import json
from ..utils import load_config, get_above_data_rate_threshold, get_need_internet

LOCALISATION = os.getenv('LOCALISATION', 'America/Montreal')

config = load_config()
max_packets = config["IDS_settings"]["DOS_QUEUE_SIZE"]
class Sniffer(Thread):
    def __init__(self, interface="wlan1", filepath="capture.pcap"):
        super().__init__()
        self.daemon = True
        self.logger=setup_logging()
        self.interface = interface
        self.stop_sniffer = Event()
        self.pause_sniffer = Event()  # To control pause/resume
        self.filepath = filepath

    def run(self):
        while not self.stop_sniffer.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.print_to_file,
                    stop_filter=self.should_stop_sniffer,
                    timeout=1  # Sniff for 1 second, then re-check events
                )
            except Exception as e:
                self.logger.info(f"[!] Sniffer error: {e}")

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.is_set()
        
    def print_to_file(self, packet):
        # Check if paused, and if it is, do not print
        if self.pause_sniffer.is_set():
            return
        wrpcap(self.filepath, packet, append=True)
        # Uncomment the line below to print all packets to the console
        #self.logger.info(f"[!] New Packet : {packet.summary()}") 
        
    def pause(self):
        self.pause_sniffer.set()  # Sets the event, causing the sniffing to pause

    def resume(self):
        self.pause_sniffer.clear()  # Clears the event, allowing sniffing to resume

    def stop(self):
        self.stop_sniffer.set()  # Stops sniffing

    def set_path(self, path):
        self.filepath = path
        self.logger.info(f"[!] New Path: {path}")


class IDSSniffer(Thread):
    def __init__(self, current_app, config_path="config.json", interface="wlan1", filepath="sniffer.pcap", max_packets=max_packets):
        super().__init__()
        self.app = current_app
        self.daemon = True
        self.config_path = config_path
        self.config = {}
        self.last_packet = None
        self.interface = interface
        self.filepath = filepath
        self.logger=setup_logging()
        self.max_packets = max_packets
        self.packet_buffer = deque(maxlen=max_packets)
        self.anomaly_detected = False
        self.packet_counter = 0
        self.port_scan_tracker = {}
        self.dos_time_tracker = {}
        self.anomalies = ["port_scan", "dos", "above_data_rate", "unusual_ips"]
        self.anomaliesPath = {
            elt: f"app/static/anomalies/{elt}" for elt in self.anomalies
        }
        self.detectedAnomaliesCount = {elt : 0 for elt in self.anomalies}
        self.anomaliesDetected = {attack_type: 
                        [] for attack_type in self.anomalies}
        # Merging variables
        self.data_rate = {}
        self.total_data_rate = 0
        self.capture_duration = self.load_capture_duration_from_config()

    def load_capture_duration_from_config(self):
        """Load capture duration from the config file."""
        try:
            with open(self.config_path) as config_file:
                config = json.load(config_file)
            return config["Data_rate"].get("Refresh_global_data_rate", 10)
        except Exception as e:
            self.logger.error(f"[!] Failed to load capture duration: {e}")
            return 10  # Default duration

    def reload_config(self):
        try:
            with open(self.config_path) as config_file:
                self.config = json.load(config_file)
        except Exception as e:
            self.logger.error(f"[!] Failed to load config: {e}")
            
    def run(self):
        with self.app.app_context():
            while True:
                try:
                    self.reload_config()
                    self.capture_duration = self.load_capture_duration_from_config()
                    sniff(
                        iface=self.interface,
                        prn=self.process_packet,
                        timeout=self.capture_duration # Sniff for capture_duration second, then re-check events
                    )
                    self.upload_data_rate()
                    self.total_data_rate = 0
                    self.data_rate = {}
                except Exception as e:
                    self.logger.info(f"[!] Sniffer error: {e}")
    
    def packet_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip not in self.data_rate:
                self.data_rate[src_ip] = 0
            self.data_rate[src_ip] += packet[IP].len
        self.total_data_rate += len(packet)


    def join(self, timeout=None):
        self.logger.info("[!] Stopping Sniffer")
        super().join(timeout)

    def upload_data_rate(self):
        with self.app.app_context():
            devices = Device.query.all()
            for device in devices:
                ipv4 = device.ipv4
                if device.id != 1:
                    # Check if the device is in the data_rate dictionary
                    if ipv4 in self.data_rate:
                        new_data_rate = DataRate(device_id=device.id, rate=self.data_rate[ipv4], date=datetime.now(pytz.timezone(LOCALISATION)))
                        db.session.add(new_data_rate)
                    else: # If the device is not in the dictionary, add 0
                        new_data_rate = DataRate(device_id=device.id, rate=0, date=datetime.now(pytz.timezone(LOCALISATION)))
                        db.session.add(new_data_rate)
            new_total_data_rate = DataRate(device_id=1, rate=self.total_data_rate, date=datetime.now(pytz.timezone(LOCALISATION)))
            db.session.add(new_total_data_rate)
            db.session.commit()


    def reset_anomaly_detection(self, timeToWait: int, anomaly: str, victim_ip: str, attacker_ip: str):
        sleep(timeToWait)
        try:
            self.logger.info(f"Current anomaly list: {self.anomaliesDetected}")
            # Find the entry in the list
            for entry in self.anomaliesDetected[anomaly]:
                if entry.get("victim_ip") == victim_ip and entry.get("attacker_ip") == attacker_ip:
                    self.anomaliesDetected[anomaly].remove(entry)
                    self.logger.info(f"[!] Resetting {anomaly} detection for {attacker_ip} on {victim_ip}")
                    return
            # If not found
            self.logger.warning(f"[!] No matching anomaly found to reset for {attacker_ip} on {victim_ip}")
        except Exception as e:
            self.logger.error(f"[!] Error resetting anomaly detection: {e}")

    def is_detected_from_port_scan(self, src_ip, dst_ip):
        return any(entry['attacker_ip'] == src_ip and entry['victim_ip'] == dst_ip for entry in self.anomaliesDetected['port_scan'])

    def is_detected_from_dos(self, src_ip, dst_ip):
        return any(entry['attacker_ip'] == src_ip and entry['victim_ip'] == dst_ip for entry in self.anomaliesDetected['dos'])    
   
    def detect_port_scan(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = set()
            if packet.haslayer('TCP'):
                dst_port = packet['TCP'].dport
                self.port_scan_tracker[src_ip].add(dst_port)
                if len(self.port_scan_tracker[src_ip]) > self.config["IDS_settings"]["PORT_SCAN_THRESHOLD"]:
                    if not any(entry['attacker_ip'] == src_ip for entry in self.anomaliesDetected['port_scan']):
                        # Check that the src_ip is the initiator and not the victim of the attack
                        if src_ip != dst_ip:
                            self.detectedAnomaliesCount['port_scan'] += 1
                            self.anomaliesDetected['port_scan'].append({'victim_ip': dst_ip, 'attacker_ip': src_ip})
                            try:
                                self.write_to_file(detectedAnomaly="port_scan")
                                attacker_device = Device.query.filter_by(ipv4=src_ip).first()
                                victim_device = Device.query.filter_by(ipv4=dst_ip).first()
                                log_anomaly(anomaly_type="port_scan", anomaly_number=self.detectedAnomaliesCount['port_scan'], attacker_id=attacker_device.id, id_victim=victim_device.id)
                                resetThread = Thread(target=self.reset_anomaly_detection, args=(self.config["IDS_settings"]["TimeToWaitAfterAnomalies"]["PORT_SCAN"], "port_scan", dst_ip, src_ip))
                                resetThread.start()
                                return True
                            except Exception as e:
                                self.logger.error(f"Error writing anomaly: {e}")
                    else:
                        self.logger.info(f"[!] Port scan from {src_ip} already detected")
                        self.logger.info(f"[!] Logging last packet")
                        self.write_to_file(detectedAnomaly="port_scan", append=True)
        return False
    
    def detect_dos(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            time_now = time()
            if src_ip not in self.dos_time_tracker:
                self.dos_time_tracker[src_ip] = {}
                if dst_ip not in self.dos_time_tracker[src_ip]:
                    self.dos_time_tracker[src_ip][dst_ip] = deque(maxlen=self.config["IDS_settings"]["DOS_QUEUE_SIZE"])
            else:
                if dst_ip not in self.dos_time_tracker[src_ip]:
                    self.dos_time_tracker[src_ip][dst_ip] = deque(maxlen=self.config["IDS_settings"]["DOS_QUEUE_SIZE"])
            self.dos_time_tracker[src_ip][dst_ip].append(time_now)
            # If the time between the first and last packet of the buffer (default size = self.config["IDS_settings"]["DOS_QUEUE_SIZE"]) is less than the threshold (freq = self.config["IDS_settings"]["DOS_QUEUE_SIZE"]/self.config["IDS_settings"]["DOS_THRESHOLD"] packets per second)
            if len(self.dos_time_tracker[src_ip][dst_ip]) == self.config["IDS_settings"]["DOS_QUEUE_SIZE"] and self.dos_time_tracker[src_ip][dst_ip][-1] - self.dos_time_tracker[src_ip][dst_ip][0] < self.config["IDS_settings"]["DOS_THRESHOLD"]:
                # if the attacker is not already in the list of detected anomalies for DoS
                if not self.is_detected_from_dos(src_ip, dst_ip):
                    # Ensure that the victim (dst_ip) is not incorrectly flagged as the attacker
                    if not self.is_detected_from_dos(dst_ip, src_ip):
                        if not self.is_detected_from_port_scan(src_ip, dst_ip) and not self.is_detected_from_port_scan(dst_ip, src_ip):
                            self.detectedAnomaliesCount['dos'] += 1
                            self.anomaliesDetected['dos'].append({'victim_ip': dst_ip, 'attacker_ip': src_ip}) 
                            try:
                                self.write_to_file(detectedAnomaly="dos")
                                attacker_device = Device.query.filter_by(ipv4=src_ip).first()
                                victim_device = Device.query.filter_by(ipv4=dst_ip).first()
                                if attacker_device is None:
                                    log_anomaly(anomaly_type="dos", anomaly_number=self.detectedAnomaliesCount['dos'], attacker_id=None, id_victim=victim_device.id)
                                    self.logger.error(f"[!] Attacker device not found in database")
                                else:
                                    log_anomaly(anomaly_type="dos", anomaly_number=self.detectedAnomaliesCount['dos'], attacker_id=attacker_device.id, id_victim=victim_device.id)
                                resetThread = Thread(target=self.reset_anomaly_detection, args=(self.config["IDS_settings"]["TimeToWaitAfterAnomalies"]["DOS"], "dos", dst_ip, src_ip))
                                resetThread.start()
                                return True
                            except Exception as e:
                                self.logger.error(f"Error writing anomaly: {e}")
                else:
                    self.write_to_file(detectedAnomaly="dos", append=True)
                    self.logger.info(f"[!] DoS from {src_ip} already detected, logging last packet")
                    return True
            elif len(self.dos_time_tracker[src_ip][dst_ip]) == self.config["IDS_settings"]["DOS_QUEUE_SIZE"] \
                and self.dos_time_tracker[src_ip][dst_ip][-1] - self.dos_time_tracker[src_ip][dst_ip][0] >= self.config["IDS_settings"]["DOS_STOP_THRESHOLD"] and any(entry['attacker_ip'] == src_ip for entry in self.anomaliesDetected['dos']):
                # If the time between the first and last packet of the buffer (default size = self.config["IDS_settings"]["DOS_QUEUE_SIZE"]) is more than the threshold (freq = self.config["IDS_settings"]["DOS_QUEUE_SIZE"]/self.config["IDS_settings"]["DOS_STOP_THRESHOLD"] packets per second and the attacker is in the list of detected anomalies for DoS
                self.logger.info(f"[!] End of DoS detected from {src_ip}")
                try:
                    self.anomaliesDetected['dos'].remove({'victim_ip': dst_ip, 'attacker_ip': src_ip})                    
                    self.logger.info(f"[!] Resetting DoS detection for {src_ip}")
                except Exception as e:
                    self.logger.error(f"[!] Error resetting DoS detection: {e}")
        return False

    def detect_above_data_rate(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            threshold = get_above_data_rate_threshold(ipv4=src_ip)
            if not threshold:
                return False
            if self.data_rate[src_ip] > threshold:
                self.logger.info(f"[!] Above data rate detected from {src_ip}")
                # Check if large packet is not already detected
                if not any(entry['attacker_ip'] == src_ip for entry in self.anomaliesDetected['above_data_rate']):
                    self.detectedAnomaliesCount['above_data_rate'] += 1
                    self.anomaliesDetected['above_data_rate'].append({'victim_ip': dst_ip, 'attacker_ip': src_ip})
                    attacker_device = Device.query.filter_by(ipv4=src_ip).first()
                    victim_device = Device.query.filter_by(ipv4=dst_ip).first()
                    try:
                        
                        self.write_to_file(detectedAnomaly="above_data_rate")
                        if attacker_device is None:
                            log_anomaly(anomaly_type="above_data_rate", anomaly_number=self.detectedAnomaliesCount['above_data_rate'], attacker_id=None, id_victim=victim_device.id)
                            self.logger.error(f"[!] Attacker device not found in database")
                        else:
                            self.logger.info(f"[!] Logging large packet first time")
                            log_anomaly(anomaly_type="above_data_rate", anomaly_number=self.detectedAnomaliesCount['above_data_rate'], attacker_id=attacker_device.id, id_victim=victim_device.id)
                        resetThread = Thread(target=self.reset_anomaly_detection, args=(self.config["IDS_settings"]["TimeToWaitAfterAnomalies"]["ABOVE_DATA_RATE"], "above_data_rate", dst_ip, src_ip))
                        resetThread.start()
                    except Exception as e:
                        self.logger.error(f"Error writing anomaly: {e}")
                    return True
                else:
                    self.logger.info(f"[!] Above Data Rate from {src_ip} already detected")
                    self.logger.info(f"[!] Logging last packet")
                    self.write_to_file(detectedAnomaly="above_data_rate", append=True)
                    return True
        return False

    def detect_unusual_ips(self, packet):
        anomaly_name = "unusual_ips"
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if not dst_ip.startswith("192.168."):
                need_internet = get_need_internet(ipv4=src_ip)
                if not need_internet:
                    self.logger.info(f"[!] Unusual destination IP detected: {dst_ip}")
                    if not any(entry['attacker_ip'] == dst_ip for entry in self.anomaliesDetected[anomaly_name]):
                        self.detectedAnomaliesCount[anomaly_name] += 1
                        self.anomaliesDetected[anomaly_name].append({'victim_ip': src_ip, 'attacker_ip': dst_ip})
                        attacker_device = Device.query.filter_by(ipv4=dst_ip).first()
                        victim_device = Device.query.filter_by(ipv4=src_ip).first()
                        try:
                            self.write_to_file(detectedAnomaly=anomaly_name)
                            if attacker_device is None:
                                log_anomaly(anomaly_type=anomaly_name, anomaly_number=self.detectedAnomaliesCount[anomaly_name], attacker_id=None, id_victim=victim_device.id)
                                self.logger.error(f"[!] Attacker device not found in database")
                            else:
                                self.logger.info(f"[!] Logging abnormal destination IP for the first time")
                                log_anomaly(anomaly_type=anomaly_name, anomaly_number=self.detectedAnomaliesCount[anomaly_name], attacker_id=attacker_device.id, id_victim=victim_device.id)
                            resetThread = Thread(target=self.reset_anomaly_detection, args=(self.config["IDS_settings"]["TimeToWaitAfterAnomalies"]["UNUSUAL_IPS"], anomaly_name, dst_ip, src_ip))
                            resetThread.start()
                        except Exception as e:
                            self.logger.error(f"Error writing anomaly: {e}")
                        return True
                    else:
                        self.logger.info(f"[!] Abnormal destination IP from {src_ip} already detected")
                        self.logger.info(f"[!] Logging last packet")
                        self.write_to_file(detectedAnomaly=anomaly_name, append=True)
                        return True
            return False



    def detect_anomalies_packet(self, packet):
        """Logic to detect anomalies from single packets"""

        port_scan_anomaly = self.detect_port_scan(packet)
        dos_scan_anomaly = self.detect_dos(packet)
        above_data_rate = self.detect_above_data_rate(packet)
        abnormal_dest_ip = self.detect_unusual_ips(packet)

            # To implement:
 
                # Unauth protocols

                # Unusual destination IPs

                # Repeated connection attempts (SYN flood)

                # DNS tunneling (abnormal long DNS queries)

                # Malicious payloads (check for known signatures, key words, ..)
 
    def process_packet(self, packet):
        self.packet_callback(packet)
        self.last_packet = packet
        self.packet_buffer.append(packet)
        self.packet_counter+=1
        self.detect_anomalies_packet(packet)
        #self.logger.info(f"[*] New packet : {packet}")
        
    def write_to_file(self, detectedAnomaly:str, append:bool=False):
        self.filepath = self.anomaliesPath[detectedAnomaly]+f"/{self.detectedAnomaliesCount[detectedAnomaly]}.pcap"
        if append:
            wrpcap(self.filepath, self.last_packet, append=append) 
        else: 
            wrpcap(self.filepath, list(self.packet_buffer), append=append) # write the max_len last packets to the file
        self.logger.info(f"[!] Anomalous packets saved to {self.filepath}")
        
           
