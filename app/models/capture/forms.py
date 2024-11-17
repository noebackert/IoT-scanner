# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, TimeField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange

class selectForm(FlaskForm):
    device = IntegerField('Device', validators=[DataRequired()], render_kw={'placeholder': 'Device'}) 
    action = StringField('Action', validators=[DataRequired()], render_kw={'placeholder': 'Action'})
    submit = SubmitField('Submit')

class CaptureTimeForm(FlaskForm):
    timeSelector = IntegerField('Time', validators=[DataRequired()], render_kw={'placeholder': 'In seconds'})
    submit = SubmitField('Submit')

class CaptureNumberForm(FlaskForm):
    numberSelector = IntegerField('Number', validators=[DataRequired(), NumberRange(min=1, max=1000)])
    submit = SubmitField('Submit')

class CapturePlayForm(FlaskForm):
    value = StringField('Play', validators=[DataRequired()], default="stop")
    submit = SubmitField('Play')