from collections.abc import Callable
from typing import Any, Iterable, Mapping
from scapy.all import sniff, wrpcap, IP, TCP
from threading import Thread, Event
from collections import deque
from .logging_config import setup_logging
from .handle_anomaly import log_anomaly
from time import time, sleep
from .sql import Device

PORT_SCAN_THRESHOLD = 20
DOS_THRESHOLD = 2
DOS_STOP_THRESHOLD = 50
timeToWaitAfterAnomalies = {
    "port_scan": 10,
    "dos": 10
}

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
    def __init__(self, current_app, interface="wlan1", filepath="sniffer.pcap", max_packets=100):
        super().__init__()
        self.app = current_app
        self.daemon = True
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
        self.anomalies = ["port_scan", "dos"]
        self.anomaliesPath = {
            elt: f"app/static/anomalies/{elt}" for elt in self.anomalies
        }
        self.detectedAnomaliesCount = {elt : 0 for elt in self.anomalies}
        self.anomaliesDetected = {attack_type: 
                        [] for attack_type in self.anomalies}
        

    def run(self):
        with self.app.app_context():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.process_packet,
                    #timeout=1  # Sniff for 1 second, then re-check events
                )
            except Exception as e:
                self.logger.info(f"[!] Sniffer error: {e}")

    def join(self, timeout=None):
        self.logger.info("[!] Stopping Sniffer")
        super().join(timeout)


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
                if len(self.port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                    if not any(entry['attacker_ip'] == src_ip for entry in self.anomaliesDetected['port_scan']):
                        #self.logger.info(f"[!] Probable port scan detected from {src_ip}")
                        self.detectedAnomaliesCount['port_scan'] += 1 # Increment the number of port scan detected
                        self.anomaliesDetected['port_scan'].append({'victim_ip': dst_ip, 'attacker_ip': src_ip})
                        try:
                            self.write_to_file(detectedAnomaly="port_scan")
                            attacker_device = Device.query.filter_by(ipv4=src_ip).first()
                            victim_device = Device.query.filter_by(ipv4=dst_ip).first()
                            log_anomaly(anomaly_type="port_scan", anomaly_number=self.detectedAnomaliesCount['port_scan'], attacker_id=attacker_device.id, id_victim=victim_device.id)
                            resetThread = Thread(target=self.reset_anomaly_detection, args=(timeToWaitAfterAnomalies['port_scan'], "port_scan", dst_ip, src_ip))
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
                    self.dos_time_tracker[src_ip][dst_ip] = deque(maxlen=100)
            else:
                if dst_ip not in self.dos_time_tracker[src_ip]:
                    self.dos_time_tracker[src_ip][dst_ip] = deque(maxlen=100)
            self.dos_time_tracker[src_ip][dst_ip].append(time_now)
            # If the time between the first and last packet of the buffer (default size = 100) is less than the threshold (freq = 100/DOS_THRESHOLD packets per second)
            if len(self.dos_time_tracker[src_ip][dst_ip]) == 100 and self.dos_time_tracker[src_ip][dst_ip][-1] - self.dos_time_tracker[src_ip][dst_ip][0] < DOS_THRESHOLD: 
                # if the attacker is not already in the list of detected anomalies for DoS
                if not self.is_detected_from_dos(src_ip, dst_ip):
                    # if the attacker is not already a victim (just replying to a DoS attack)
                    if not self.is_detected_from_dos(dst_ip, src_ip):
                        # check if port_scan is already detected for theses IPs
                        if not self.is_detected_from_port_scan(src_ip, dst_ip) and not self.is_detected_from_port_scan(dst_ip, src_ip):
                            self.logger.info(f"[!] Probable DoS detected from {src_ip} to {dst_ip}")
                            self.logger.info(f"[!] self.dos_time_tracker[{src_ip}]: {self.dos_time_tracker[src_ip][dst_ip]}")
                            self.detectedAnomaliesCount['dos'] += 1
                            self.anomaliesDetected['dos'].append({'victim_ip': dst_ip, 'attacker_ip': src_ip})
                            try:
                                self.write_to_file(detectedAnomaly="dos")
                                attacker_device = Device.query.filter_by(ipv4=src_ip).first()
                                victim_device = Device.query.filter_by(ipv4=dst_ip).first()
                                log_anomaly(anomaly_type="dos", anomaly_number=self.detectedAnomaliesCount['dos'], attacker_id=attacker_device.id, id_victim=victim_device.id)
                                resetThread = Thread(target=self.reset_anomaly_detection, args=(timeToWaitAfterAnomalies['dos'], "dos", dst_ip, src_ip))
                                resetThread.start()
                                return True
                            except Exception as e:
                                self.logger.error(f"Error writing anomaly: {e}")
                    else:
                        self.write_to_file(detectedAnomaly="dos", append=True)
            elif len(self.dos_time_tracker[src_ip][dst_ip]) == 100 \
                and self.dos_time_tracker[src_ip][dst_ip][-1] - self.dos_time_tracker[src_ip][dst_ip][0] >= DOS_STOP_THRESHOLD and any(entry['attacker_ip'] == src_ip for entry in self.anomaliesDetected['dos']):
                # If the time between the first and last packet of the buffer (default size = 100) is more than the threshold (freq = 100/DOS_STOP_THRESHOLD packets per second and the attacker is in the list of detected anomalies for DoS
                self.logger.info(f"[!] End of DoS detected from {src_ip}")
                try:
                    self.anomaliesDetected['dos'].remove({'victim_ip': dst_ip, 'attacker_ip': src_ip})                    
                    self.logger.info(f"[!] Resetting DoS detection for {src_ip}")
                except Exception as e:
                    self.logger.error(f"[!] Error resetting DoS detection: {e}")
        return False

   

    def detect_anomalies_packet(self, packet):
        """Logic to detect anomalies from single packets"""
        port_scan_anomaly = self.detect_port_scan(packet)
        dos_scan_anomaly = self.detect_dos(packet)


            # To implement:
                # Ping flood Dos Check
         

                # Suspicious packet size check

                # Unauth protocols

                # Unusual destination IPs

                # Repeated connection attempts (SYN flood)

                # DNS tunneling (abnormal long DNS queries)

                # Malicious payloads (check for kno # Dos Check

                # Suspicious packet size check

                # Unauth protocols

                # Unusual destination IPs

                # Repeated connection attempts (SYN flood)

                # DNS tunneling (abnormal long DNS queries)

                # Malicious payloads (check for known signatures, key words, ..)
 
    def process_packet(self, packet):
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
        
   