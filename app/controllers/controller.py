"""
Business logic for the main application
"""
from flask import Flask, render_template, url_for, redirect, flash, request
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from ..models.settings import SettingsForm
from ..models.sql import db, bcrypt, UserDB
from ..models.auth import LoginForm, RegisterForm
from functools import wraps
from ..utils import setup_logging, load_config, save_config


logger = setup_logging()


def admin_required(func):
    """A decorator to check if the user is an admin."""
    @wraps(func)  # Preserve function metadata
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.role == 999:
                return func(*args, **kwargs)
            else:
                flash('You need to be Admin to access this feature', 'error')
                return redirect(url_for('blueprint.login'))  # Ensure this endpoint exists
        else:
            flash('Please log in to access this feature', 'error')
            return redirect(url_for('blueprint.login'))  # Ensure this endpoint exists
    return wrapper


def index():
    """
        Handles the logic for / (home page)

        Args:
            - None.

        Returns:
            - rendered index.html template
        """

    return render_template('index.html')

def login():
    """
        Handles the logic for /login page

        Args:
            - None.

        Returns:
            - rendered .html template (dashboard.html if login success or login.html if login fail)
        """
    #bcrypt = get_bcrypt()
    form = LoginForm()
    if form.validate_on_submit():
        user = UserDB.query.filter_by(username=form.username.data).first()
        remember_me = True if form.remember_me.data else False
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=remember_me)
                return redirect(url_for('blueprint.hotspot'))
        flash('Login or password incorrect!', 'Error')
    return render_template('login.html', form=form)



@login_required
def about():
    """
        Handles the logic for /dashboard page
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - rendered dashboard.html template
        """
    username = current_user.username
    return render_template('about.html', username=username)

@login_required
def logout():
    """
        Handles the logic for /logout page
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - redirect to login page
        """
    logout_user()
    return redirect(url_for('blueprint.login'))

@admin_required
def register():
    """
        Handles the logic for /register page

        Args:
            - None.

        Returns:
            - rendered .html template
        """
    #bcrypt = get_bcrypt()
    form = RegisterForm()

    if form.validate_on_submit():
        from app import bcrypt
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = UserDB(username=form.username.data, password=hashed_password, role=0)
        db.session.add(new_user)
        db.session.commit()
        flash('The new account has been created! You are now able to log in', 'Success')        
        return redirect(url_for('blueprint.login'))
    return render_template('register.html', form=form, username=current_user.username)

@admin_required
def settings():
    """
        Handles the logic for /settings page
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - rendered settings.html template
        """
    config = load_config()
    content = {
        "form": SettingsForm(data={
        "refreshRate": config["Data_rate"].get("Refresh_global_data_rate", 10),
        "refreshRateConnectedDevices": config["Data_rate"].get("Refresh_connected_devices", 10),
        "dosThreshold": config["IDS_settings"].get("DOS_THRESHOLD", 20),
        "dosStopThreshold": config["IDS_settings"].get("DOS_STOP_THRESHOLD", 50),
        "dosQueueSize": config["IDS_settings"].get("DOS_QUEUE_SIZE", 1000),
        "portScanThreshold": config["IDS_settings"].get("PORT_SCAN_THRESHOLD", 20),
        "timeToWaitAfterAnomaliesPortScan": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("port_scan", 60),
        "timeToWaitAfterAnomaliesDos": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("dos", 60),
        "timeToWaitAfterAnomaliesLargePacket": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("above_data_rate", 60),
        "timeToWaitAfterAnomaliesUnusualIp": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("unusual_ips", 60),
        "timeToWaitAfterAnomaliesDnsTunneling": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("dns_tunneling", 60),
        "timeToWaitAfterAnomaliesMaliciousPayload": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("malicious_payload", 60),
        "timeToWaitAfterAnomaliesArpSpoofing": config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("arp_spoofing", 60)
    })
    }
    if content["form"].validate_on_submit():
        action = request.form.get("action")
        if action == "save":
            # Handle settings form submission
            oldConfigJson = load_config()
            # update the changed values in the config file
            configJson = oldConfigJson
            configJson["Data_rate"]["Refresh_global_data_rate"] = content["form"].data["refreshRate"]
            configJson["Data_rate"]["Refresh_connected_devices"] = content["form"].data["refreshRateConnectedDevices"]
            configJson["IDS_settings"]["DOS_THRESHOLD"] = content["form"].data["dosThreshold"]
            configJson["IDS_settings"]["DOS_STOP_THRESHOLD"] = content["form"].data["dosStopThreshold"]
            configJson["IDS_settings"]["DOS_QUEUE_SIZE"] = content["form"].data["dosQueueSize"]
            configJson["IDS_settings"]["PORT_SCAN_THRESHOLD"] = content["form"].data["portScanThreshold"]
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["port_scan"] = content["form"].data["timeToWaitAfterAnomaliesPortScan"]
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["dos"] = content["form"].data["timeToWaitAfterAnomaliesDos"]
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["above_data_rate"] = content["form"].data["timeToWaitAfterAnomaliesLargePacket"]   
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["unusual_ips"] = content["form"].data["timeToWaitAfterAnomaliesUnusualIp"]  
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["dns_tunneling"] = content["form"].data["timeToWaitAfterAnomaliesDnsTunneling"] 
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["malicious_payload"] = content["form"].data["timeToWaitAfterAnomaliesMaliciousPayload"]
            configJson["IDS_settings"]["TimeToWaitAfterAnomalies"]["arp_spoofing"] = content["form"].data["timeToWaitAfterAnomaliesArpSpoofing"]
            save_config(configJson)
            flash('Settings saved!', 'success')
            return render_template(url_for('blueprint.settings')+'.html', username=current_user.username, content=content)

        elif action == "default":
            # Handle reset to default form submission
            configJson = load_config("config_default.json")
            save_config(configJson)
            flash('Settings reset to default!', 'success')
        # refresh content
        
        return redirect(url_for('blueprint.settings'))
    return render_template(url_for('blueprint.settings')+'.html', username=current_user.username, content=content)