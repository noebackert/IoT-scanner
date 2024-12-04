# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange
from ..utils import load_config




class SettingsForm(FlaskForm):
    """ Form to edit settings """
    config = load_config()
    refreshRate = IntegerField('Global Data Rate refresh delay (seconds)', validators=[DataRequired(), NumberRange(min=1, max=300)], default=config["Data_rate"].get("Refresh_global_data_rate", 10), render_kw={"placeholder": "Refresh rate (default = 10)"})
    refreshRateConnectedDevices = IntegerField('Connected Devices refresh delay (seconds)', validators=[DataRequired(), NumberRange(min=1, max=300)], default=config["Data_rate"].get("Refresh_connected_devices", 10), render_kw={"placeholder": "Refresh rate (default = 10)"})
    dosThreshold=IntegerField('dos threshold', validators=[DataRequired(), NumberRange(min=1, max=100)], default=config["IDS_settings"].get("DOS_THRESHOLD", 20), render_kw={"placeholder": "dos threshold (default = 20)"})
    dosStopThreshold=IntegerField('dos stop threshold', validators=[DataRequired(), NumberRange(min=1, max=100)], default=config["IDS_settings"].get("DOS_STOP_THRESHOLD", 50), render_kw={"placeholder": "dos stop threshold (default = 10)"})
    dosQueueSize=IntegerField('dos queue size', validators=[DataRequired(), NumberRange(min=1, max=10000)], default=config["IDS_settings"].get("DOS_QUEUE_SIZE", 1000), render_kw={"placeholder": "dos queue size (default = 1000)"})
    portScanThreshold=IntegerField('Port scan threshold', validators=[DataRequired(), NumberRange(min=1, max=100)], default=config["IDS_settings"].get("PORT_SCAN_THRESHOLD", 20), render_kw={"placeholder": "Port scan threshold (default = 20)"})
    timeToWaitAfterAnomaliesPortScan=IntegerField('Time to wait after anomalies port scan', validators=[DataRequired(), NumberRange(min=1, max=100)], default=config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("port_scan", 60), render_kw={"placeholder": "Time to wait after anomalies port scan (default = 60)"})
    timeToWaitAfterAnomaliesDos=IntegerField('Time to wait after anomalies dos', validators=[DataRequired(), NumberRange(min=1, max=100)], default=config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("dos", 60), render_kw={"placeholder": "Time to wait after anomalies dos (default = 60)"})
    timeToWaitAfterAnomaliesLargePacket=IntegerField('Time to wait after anomalies large packet', validators=[DataRequired(), NumberRange(min=1, max=100)], default=config["IDS_settings"]["TimeToWaitAfterAnomalies"].get("above_data_rate", 60), render_kw={"placeholder": "Time to wait after anomalies large packet (default = 60)"})
    submit = SubmitField('Save')
    submitDefault = SubmitField('Reset to default')
