# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, FloatField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange

class HotspotForm(FlaskForm):
    submit = SubmitField('Submit')

class EditDeviceForm(FlaskForm):
    """
    Form to edit device information
    """
    mac = StringField('MAC Address', validators=[DataRequired()])
    name = StringField('Name', validators=[], render_kw={"placeholder": "Name"})
    vendor = StringField('Vendor', validators=[], render_kw={"placeholder": "Vendor"})
    model = StringField('Model', validators=[], render_kw={"placeholder": "Model"})
    version = StringField('Version', validators=[], render_kw={"placeholder": "Version"})
    aboveDataRateThreshold = FloatField('Large Packet Threshold (bytes)', validators=[NumberRange(min=0, max=1e9)], render_kw={"placeholder": "Large Packet Threshold (bytes)"}, default=int(1e6))
    needInternet = BooleanField('Need Internet', validators=[], render_kw={"placeholder": "Need Internet"}, default=True)
    submit = SubmitField('Submit')