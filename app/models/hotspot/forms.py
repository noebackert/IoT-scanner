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
    scan_status = BooleanField(validators=[],label="ON/OFF SCAN", render_kw={"placeholder": "scan_status"}, default=False)

    submit = SubmitField('Submit')