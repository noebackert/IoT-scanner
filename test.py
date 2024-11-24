anomalies = ["Port_scan", "DoS"]
anomaliesDetected = {attack_type: 
                        [{'victim_ip': None,
                        'attacker_ip': None}] for attack_type in anomalies}

print(anomaliesDetected)

   if src_ip not in self.dos_tracker:
                self.dos_tracker[src_ip] = 0
            if self.last_packet['IP'].src == src_ip:
                time_now = time()
                self.dos_time_tracker[src_ip].append(time_now)
                if len(self.dos_time_tracker[src_ip]) == 100 and self.dos_time_tracker[src_ip][-1] - self.dos_time_tracker[src_ip][0] < DOS_THRESHOLD:
                    self.logger.info(f"[!] {self.dos_time_tracker[src_ip]}")
                    self.logger.info(f"[!] Time between last 100 packets : {self.dos_time_tracker[src_ip][-1] - self.dos_time_tracker[src_ip][0]}")
                    if 'dos' not in self.anomaliesDetected[src_ip]:
                        self.logger.info(f"[!] Probable DoS detected from {src_ip} to {victim_ip}")
                        self.detectedAnomaliesCount['dos'] += 1
                        self.anomaliesDetected[src_ip].add('dos')
                        self.victimDos[victim_ip] = src_ip
                        # Check if that's not just the victim replying to the attacker
                        if self.victimDos[src_ip] == victim_ip:
                            self.victimDos.pop(victim_ip)
                            return
                        try:
                            self.write_to_file(detectedAnomaly="dos")
                            attacker_device = Device.query.filter_by(ipv4=src_ip).first()
                            log_anomaly(anomaly_type="dos", anomaly_number=self.detectedAnomaliesCount['dos'], attacker_id=attacker_device.id, id_victim=victim_device.id)
                        except Exception as e:
                            self.logger.error(f"Error writing anomaly: {e}")
                    else:
                        if self.last_packet['IP'].src == src_ip: # If the last packet was from the attacker
                            self.write_to_file(detectedAnomaly="dos", append=True)
                elif len(self.dos_time_tracker[src_ip]) == 100 and self.dos_time_tracker[src_ip][-1] - self.dos_time_tracker[src_ip][0] >= DOS_STOP_THRESHOLD and 'dos' in self.anomaliesDetected[src_ip]:
                    self.logger.info(f"[!] End of DoS detected from {src_ip}")
                    try:
                        self.anomaliesDetected[src_ip].remove('dos')
                        self.logger.info(f"[!] Resetting DoS detection for {src_ip}")
                    except Exception as e:
                        self.logger.error(f"[!] Error resetting DoS detection: {e}")
                self.logger.info(f"[!] Time between last 100 packets : {self.dos_time_tracker[src_ip][-1] - self.dos_time_tracker[src_ip][0]}")
                self.logger.info(f"[!] dos in anomaliesDetected[[{src_ip}]] : {'dos' in self.anomaliesDetected[src_ip]}")
                self.logger.info(f"[!] len(self.dos_time_tracker[{src_ip}]) : {len(self.dos_time_tracker[src_ip])}")
              