# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Communicates with the SQLite database
"""
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv

# Initializes a database object that enables interaction with the database using SQLAlchemy's functionalities.
db = SQLAlchemy()
bcrypt = Bcrypt()

class UserDB(db.Model, UserMixin):
    """
    Represents a User model in the database.
    
    Attributes:
        - id: Integer field, primary key of the User.
        - username: String field, username of the User, must be unique and not nullable.
        - password: String field, password of the User, not nullable.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, nullable=False, unique=False)

class Device(db.Model):
    """
    Represents a Device model in the database.
    
    Attributes:
        - id: Integer field, primary key of the Device.
        - name: String field, name of the Device.
        - ipv4: String field, IPv4 address of the Device, not nullable.
        - ipv6: String field, IPv6 address of the Device.
        - mac: String field, MAC address of the Device, not nullable.
        - vendor: String field, vendor of the Device, not nullable.
        - model: String field, model of the Device.
        - version: String field, version of the Device.
        - is_online: Boolean field, status of the Device.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=True)
    ipv4 = db.Column(db.String(15), nullable=False)
    ipv6 = db.Column(db.String(39), nullable=True)
    mac = db.Column(db.String(17), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=True)
    version = db.Column(db.String(50), nullable=True)
    is_online = db.Column(db.Boolean, default=True)
    avg_ping = db.Column(db.Float, default=0)

class Monitoring(db.Model):
    """
    Represents a Monitoring model in the database.
    
    Attributes:
        - id: Integer field, primary key of the Monitoring.
        - device_id: Integer field, foreign key to the Device.
        - ping: Integer field, ping of the Monitoring.
    """
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    ip = db.Column(db.String(15), nullable=False)
    ping = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False)

class Capture(db.Model):
    """
    Represents a Capture model in the database.
    
    Attributes:
        - id: Integer field, primary key of the Capture.
        - device_id: Integer field, foreign key to the Device.
        - file_path: String field, path to the Capture file.
        - date: DateTime field, date of the Capture.
    """
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)


def create_admin():
    """Create an admin user."""
    # Create an admin user if one doesn't exist
    if not UserDB.query.filter_by(username="admin").first():
        hashed_password = bcrypt.generate_password_hash(os.getenv("ADMIN_DEFAULT_PASSWORD")).decode('utf-8')
        new_user = UserDB(username="admin", password=hashed_password, role=999)
        db.session.add(new_user)
        db.session.commit()
        print("Admin user created successfully!")


def create_hotspot_device():
    """Create a hotspot device."""
    # Create a hotspot device if one doesn't exist
    new_device=Device.query.filter_by(mac=os.getenv("HOTSPOT_MAC")).first()
    if not new_device:
        new_device = Device(name=os.getenv("HOTSPOT_SSID"), ipv4=os.getenv("HOTSPOT_IPV4"), mac=os.getenv("HOTSPOT_MAC"), vendor=os.getenv("HOTSPOT_VENDOR"))
        db.session.add(new_device)
        db.session.commit()
        print("Hotspot device created successfully!")
