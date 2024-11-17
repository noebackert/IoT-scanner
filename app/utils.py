from flask import current_app
from app.models.sql import Device, Monitoring, db


def with_app_context(func):
    """A decorator to push the Flask app context to threaded functions."""
    def wrapper(*args, **kwargs):
        with current_app.app_context():
            return func(*args, **kwargs)
    return wrapper

def update_avg_ping():
    """Update the average ping of all devices."""
    devices = Device.query.all()  # Get all devices
    
    for device in devices:
        pings = Monitoring.query.filter_by(device_id=device.id) \
            .order_by(Monitoring.date.desc()) \
            .limit(5).all()  # Use .all() to fetch results as a list

        if pings:
            # Calculate the average ping
            avg_ping = sum(ping.ping for ping in pings) / len(pings)
            device.avg_ping = avg_ping  # Update the device's avg_ping
        
        else:
            device.avg_ping = 0  # No pings available, set to None or 0 if preferred
        
    # Commit all changes at once to minimize database overhead
    db.session.commit()
    return True

def update_content(content):
    """
    Update the content of the pages.
    """
    devices = Device.query.all()
    content['devices'] = [d for d in devices]
    content['selected_devices'] = [d for d in devices if d.selected]
    return content