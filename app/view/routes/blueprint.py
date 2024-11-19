"""
Configures the address paths (URL routes)
"""
from flask import Blueprint
from ...controllers.controller import index, login, register, dashboard, logout, about
from ...controllers.user_profile.controller import user_profile
from ...controllers.hotspot.controller import hotspot, edit_device, delete_device
from ...controllers.capture.controller import capture, log

blueprint = Blueprint('blueprint', __name__, template_folder='../templates', static_folder='../../assets')

# Home
blueprint.route('/')(index)
blueprint.route('/login', methods=['GET', 'POST'])(login)
blueprint.route('/register', methods=['GET', 'POST'])(register)
blueprint.route('/dashboard', methods=['GET', 'POST'])(dashboard)
blueprint.route('/about', methods=['GET', 'POST'])(about)
blueprint.route('/logout', methods=['GET', 'POST'])(logout)

# User Profile
blueprint.route('/user_profile/user_profile', methods=['GET', 'POST'])(user_profile)

# Hotspot
blueprint.route('/hotspot/hotspot', methods=['GET', 'POST'])(hotspot)
blueprint.route('/hotspot/edit_device', methods=['GET', 'POST'])(edit_device)
blueprint.route('/hotspot/delete_device', methods=['GET', 'POST'])(delete_device)

# Capture
blueprint.route('/capture/capture', methods=['GET', 'POST'])(capture)
blueprint.route('/capture/log', methods=['GET', 'POST'])(log)