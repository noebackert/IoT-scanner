# Intrusion Detection system for course INSE6170 @ Concordia University




## To start the access point (AP) and the IDS

https://forums.kali.org/archived/showthread.php?154696-Setting-up-Kali-as-a-Router-Wireless-Access-Point

```sh
sudo bash ./script_hostapd.sh # to start the hotspot
docker compose up --build # build the docker of the IDS
```

## How to use ?
1. Scan devices connected to the access point in /hotspot/hotspot
    - scan is available with the button "Scan new devices"
    - once a device is detected, it is added to the database and shown on the connected device table
    - once a device has been scanned, it is being monitored and we can see in real-time (all 10 seconds) if his connection stopped 
2. Edit devices properties like name, vendor, model, version
3. Capture packets (live capture, number of packets or time-based)


## How to test functionalty:

1. Port Scan detection:
    nmap TARGET_IP 
2. Ping flood DoS detection:
    hping3 -1 -a SPOOFED_IP TARGET_IP --flood
3. SYN flood DoS detection
    sudo hping3 -S -p TARGET_PORT -a FAKE_IP --flood TARGET_IP


# Author
[Noé Backert](mailto:noe.backert@gmail.com)