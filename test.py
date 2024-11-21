anomalies = {}
src_ip = '192.168.10.1'

if 'port_scan' not in anomalies.get(src_ip, set()):
    print('port_scan not detected')
else:
    print('port_scan detected')

anomalies[src_ip] = set()
anomalies[src_ip].add('port_scan')



if 'port_scan' not in anomalies.get(src_ip, set()):
    print('port_scan not detected')
else:
    print('port_scan detected')