from ipaddress import IPv4Address



class Device:
    def __init__(self, MAC:str=None, IP:IPv4Address=None, hostname:str=None, vendor:str=None, status:bool=False):
        self.MAC = MAC
        self.IP = IP
        self.hostname = IP
        self.vendor = vendor
        self.status = status

