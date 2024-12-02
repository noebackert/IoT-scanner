"""
Business logic for the main application
"""
import logging
from flask import Flask, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import os
from .sql import db, bcrypt, UserDB, create_admin, create_hotspot_device
from .sniffer import IDSSniffer
from .logging_config import setup_logging

INTERFACE = os.getenv('INTERFACE', "wlan1")

class PyFlaSQL():
    """Create the application PyFlaSQL"""
    def __init__(self):
        self.logger = setup_logging()
        self.myapp = self.create_app("config")  # Creating the app using the config file
        self.sniffer = IDSSniffer(self.myapp, "config.json", INTERFACE, "sniffer.pcap", 1000)
        with self.myapp.app_context():
            db.create_all()
            create_admin()
            create_hotspot_device()
            if os.environ.get("WERKZEUG_RUN_MAIN")=="true": ## Prevent creating 2 sniffers during debug mode
                self.logger.info("[!] Sniffer created")
                self.sniffer.start()
        # debug - print the URL map of blueprint (check the console)
        # print(self.myapp.url_map)
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.myapp)
        self.login_manager.login_view = 'blueprint.login'
        @self.login_manager.user_loader
        def load_user(user_id):
            return UserDB.query.get(int(user_id))

    def create_app(self, config_path="config"):
        app = Flask(__name__)
        bcrypt.init_app(app)
        app.config.from_object(config_path)  # Configuring from Python Files
        db.init_app(app)
        app.config['DEBUG'] = True  # Force debug mode for testing
        from ..view.routes.blueprint import blueprint
        app.register_blueprint(blueprint, url_prefix='/')    
        return app
