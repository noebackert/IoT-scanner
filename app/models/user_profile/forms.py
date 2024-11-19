# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, TimeField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange

class changePassword(FlaskForm):
    oldPassword = PasswordField('Old Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={'placeholder': 'Old password'}) 
    newPassword = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={'placeholder': 'New password'})
    confirmPassword = PasswordField('Confirm new password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={'placeholder': 'Confirm password'})
    submit = SubmitField('Submit')
