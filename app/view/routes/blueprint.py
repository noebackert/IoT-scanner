"""
Configures the address paths (URL routes)
"""
from flask import Blueprint
from ...controllers.controller import index, login, register, logout, about
from ...controllers.user_profile.controller import user_profile, modify_password
from ...controllers.hotspot.controller import hotspot, edit_device, delete_device, get_data, scan
from ...controllers.capture.controller import capture, log, delete_log
from ...controllers.dashboard.controller import dashboard, get_data_rate, get_anomalies

blueprint = Blueprint('blueprint', __name__, template_folder='../templates', static_folder='../../assets')

# Home
blueprint.route('/')(index)
blueprint.route('/login', methods=['GET', 'POST'])(login)
blueprint.route('/register', methods=['GET', 'POST'])(register)
blueprint.route('/about', methods=['GET', 'POST'])(about)
blueprint.route('/logout', methods=['GET', 'POST'])(logout)

# User Profile
blueprint.route('/user_profile/user_profile', methods=['GET', 'POST'])(user_profile)
blueprint.route('/user_profile/modify_password', methods=['GET', 'POST'])(modify_password)

# Hotspot
blueprint.route('/hotspot/hotspot', methods=['GET', 'POST'])(hotspot)
blueprint.route('/hotspot/edit_device', methods=['GET', 'POST'])(edit_device)
blueprint.route('/hotspot/delete_device', methods=['GET', 'POST'])(delete_device)
blueprint.route('/hotspot/get_data', methods=['GET','POST'])(get_data)
blueprint.route('/hotspot/scan', methods=['POST'])(scan)

# Capture
blueprint.route('/capture/capture', methods=['GET', 'POST'])(capture)
blueprint.route('/capture/log', methods=['GET', 'POST'])(log)
blueprint.route('/capture/delete_log', methods=['GET', 'POST'])(delete_log)

# Dashboard
blueprint.route('/dashboard/dashboard', methods=['GET', 'POST'])(dashboard)
blueprint.route('/dashboard/get_data_rate', methods=['GET','POST'])(get_data_rate)
blueprint.route('/dashboard/get_anomalies', methods=['GET','POST'])(get_anomalies)