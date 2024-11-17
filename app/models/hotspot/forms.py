# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange

class HotspotForm(FlaskForm):
    submit = SubmitField('Submit')

class EditDeviceForm(FlaskForm):
    """
    Form to edit device information
    """
    mac = StringField('MAC Address', validators=[DataRequired()])
    # name with max length of 10 characters
    name = StringField('Name', validators=[], render_kw={"placeholder": "Name"})
    vendor = StringField('Vendor', validators=[], render_kw={"placeholder": "Vendor"})
    model = StringField('Model', validators=[], render_kw={"placeholder": "Model"})
    version = StringField('Version', validators=[], render_kw={"placeholder": "Version"})
    submit = SubmitField('Submit')