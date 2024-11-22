from collections.abc import Callable
from typing import Any, Iterable, Mapping
from scapy.all import sniff, wrpcap, IP, TCP
from threading import Thread, Event
from collections import deque
from .logging_config import setup_logging
from .handle_anomaly import log_anomaly
from time import time

PORT_SCAN_THRESHOLD = 20
DOS_THRESHOLD = 10

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
    def __init__(self, current_app, interface="wlan1", filepath="sniffer.pcap", max_packets=1000):
        super().__init__()
        self.app = current_app
        self.daemon = True
        self.last_packet = None
        self.interface = interface
        self.filepath = filepath
        self.logger=setup_logging()
        self.stop_sniffer = Event()
        self.pause_sniffer = Event()  # To control pause/resume
        self.max_packets = max_packets
        self.packet_buffer = deque(maxlen=max_packets)
        self.anomaly_detected = False
        self.packet_counter = 0
        self.port_scan_tracker = {}
        self.dos_tracker = {}
        self.anomalies = ["port_scan", "dos"]
        self.anomaliesPath = {
            elt: f"app/static/anomalies/{elt}" for elt in self.anomalies
        }
        self.detectedAnomaliesCount = {elt : 0 for elt in self.anomalies}
        self.last_anomaly_write_time = {}
        self.anomaliesDetected = {}

    def run(self):
        with self.app.app_context():
            while not self.stop_sniffer.is_set():
                try:
                    sniff(
                        iface=self.interface,
                        prn=self.process_packet,
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
    
    def detect_anomalies_packet(self, packet):
        """Logic to detect anomalies from single packets"""
        if packet.haslayer(IP):
            # Anomalies from Internet Protocols packets
            src_ip = packet[IP].src

            if packet.haslayer('TCP'):
                # Anomalies from TCP packets
                dst_port = packet['TCP'].dport

                # Track unique ports per IP for port scan detection
                if src_ip not in self.port_scan_tracker:
                    self.port_scan_tracker[src_ip] = set()
                self.port_scan_tracker[src_ip].add(dst_port)
                # Check for port scan anomalies using thresholds
                if len(self.port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                    # Check if 'port_scan' is not already in the anomalies set for the IP
                    if 'port_scan' not in self.anomaliesDetected.get(src_ip, set()):
                        self.logger.info(f"[!] Probable port scan detected from {src_ip}")
                        self.detectedAnomaliesCount['port_scan'] += 1
                        self.logger.info(f"[!] {self.anomaliesDetected}")
                        
                        # Add 'port_scan' to the anomalies for this IP, without resetting the set
                        if src_ip not in self.anomaliesDetected:
                            self.anomaliesDetected[src_ip] = set()     
                        self.anomaliesDetected[src_ip].add('port_scan')
                        self.logger.info(f"[!] set of {src_ip} : {self.anomaliesDetected[src_ip]}")
                        # Check if enough time has passed since the last write
                        current_time = time()
                        if (src_ip not in self.last_anomaly_write_time or
                            current_time - self.last_anomaly_write_time[src_ip] > 1):  # 1-second cooldown to prevent high speed port scan to trigger multiple writes
                            
                            self.last_anomaly_write_time[src_ip] = current_time

                            try:
                                self.write_to_file(detectedAnomaly="port_scan")
                                log_anomaly("port_scan", self.detectedAnomaliesCount['port_scan'])
                            except Exception as e:
                                self.logger.error(f"Writing error {e}")

                # dos Detection: If the source IP is sending a large number of packets, flag it
          


    def process_packet(self, packet):
        self.last_packet = packet
        self.packet_buffer.append(packet)
        self.packet_counter+=1
        self.detect_anomalies_packet(packet)
        #self.logger.info(f"[*] New packet : {packet}")
        
    def write_to_file(self, detectedAnomaly:str):
        self.filepath = self.anomaliesPath[detectedAnomaly]+f"/{self.detectedAnomaliesCount[detectedAnomaly]}.pcap"
        wrpcap(self.filepath, list(self.packet_buffer)) # write the max_len last packets to the file
        self.logger.info(f"[!] Anomalous packets saved to {self.filepath}")
        
    def pause(self):
        self.pause_sniffer.set()  # Sets the event, causing the sniffing to pause

    def resume(self):
        self.pause_sniffer.clear()  # Clears the event, allowing sniffing to resume

    def stop(self):
        self.stop_sniffer.set()  # Stops sniffing

    def set_path(self, path):
        self.filepath = path
        self.logger.info(f"[!] New Path: {path}")