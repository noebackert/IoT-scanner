# Intrusion Detection system for course INSE6170 @ Concordia University

## Requirements:
- A Linux environment (Windows not yet supported as it uses the network host mode from docker)
- 2 network interfaces (configurable in the script : `./script_hostapd.sh`)


## How to use ?
1. Scan devices connected to the access point
- scan is available with the button "Scan new devices"
- once a device is detected, it is added to the database and shown on the connected device table
- once a device has been scanned, it is being monitored and we can see in real-time (all 3 seconds) if his connection stopped 
2. Edit devices properties like name, vendor, model, version
3. Capture packets (live capture, number of packets or time-based)
4. Monitor common threats in the backgroud

## How it works

### Access Point (AP)
The AP is a hotspot that is created using hostapd and dnsmasq. It is used to connect devices to the network and monitor them. 
The AP is created using a linux device. 
The configuration is in `/etc/hostapd/hostapd.conf` 

### Intrusion Detection System (IDS)
The IDS is composed of 3 docker containers used to monitor the devices connected to the AP. It uses a script to capture packets and monitor the devices. 

#### 1. Database Container
The first container is the PostgreSQL database which is used to store the devices that are connected to the AP and the information about them.
All configurations have to be put inside the .env file

The database container requires the following env variables:
- POSTGRES_DB
- POSTGRES_USER
- POSTGRES_PASSWORD

#### 2. PGAdmin Container
The PGAdmin container is used to monitor the database and debug it more easily. It is accessible through a web browser at `http://localhost`.

The PGAdmin Container requires the following env variables:
- PGADMIN_DEFAULT_EMAIL
- PGADMIN_DEFAULT_PASSWORD

I also added a file servers.json to automatically connect to the good database when going accessing PGAdmin.

#### 3. IoT-Scanner Container
The IoT-Scanner container is used to scan the devices connected to the AP, monitor them and capture packets.

The IoT-Scanner Container requires the following env variables:
- FLASK_APP
- FLASK_ENV
- SECRET_KEY
- SQLALCHEMY_DATABASE_URI (to connect to the SQL db)
- ADMIN_DEFAULT_PASSWORD
- INTERFACE (where the AP is running)
- HOTSPOT_SSID
- HOTSPOT_IPV4
- HOTSPOT_MAC
- HOTSPOT_VENDOR
- LOCALISATION (for date timezones)



### Access Point (AP)
To start the AP, run the following command in the root directory:

```sh
sudo bash ./script_hostapd.sh
```

### Intrusion Detection System (IDS)
To start the IDS (db + pgadmin + web app), run the following command in the root directory:

```sh
docker compose up --build
```

## Resources
- [Hostapd Access Point Script : forums.kali.org](https://forums.kali.org/archived/showthread.php?154696-Setting-up-Kali-as-a-Router-Wireless-Access-Point)

- [PyFlaSQL Framework](https://github.com/noebackert/PyFlaSQL-Framework)

## How to test functionalty:

1. Port Scan detection:
    nmap TARGET_IP 
2. Ping flood DoS detection:
    hping3 -1 -a SPOOFED_IP TARGET_IP --flood
3. SYN flood DoS detection
    sudo hping3 -S -p TARGET_PORT -a FAKE_IP --flood TARGET_IP


## Insert to db:
INSERT INTO device (name, ipv4, ipv6, mac, vendor, model, version, is_online, avg_ping, average_data_rate)
VALUES ('test', '192.168.10.3', NULL, '4A:42:42:42:42', 'Google', NULL, NULL, TRUE, 0, 0);


# Author
[Noé Backert](mailto:noe.backert@gmail.com)