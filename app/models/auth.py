# This file is part of PyFlaSQL.
# Original author: Raphael Viera (raphael.viera@emse.fr)
# Contribution : ISMIN student X (ismin.student@etu.emse.fr)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError

from .sql import db, UserDB


class RegisterForm(FlaskForm):
    """
    Represents a registration form for user registration.

    Attributes:
        - username: StringField with validators for input required and length constraints,
        and a placeholder for username input.
        - password: PasswordField with validators for input required and length constraints,
        and a placeholder for password input.
        - submit: SubmitField with label 'Register' for submitting the form.
"""
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        """
        Validates the uniqueness of the username input.

        Args:
            - username: StringField for username input.

        Raises:
            - ValidationError: if the username already exists in the database.
        """
        existing_user_username = UserDB.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    """
    Represents a login form for user authentication.

    Attributes:
        - username: StringField with validators for input required and length constraints,
        and a placeholder for username input.
        - password: PasswordField with validators for input required and length constraints,
        and a placeholder for password input.
        - submit: SubmitField with label 'Login' for submitting the form.
    """
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "    "})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    
    remember_me = BooleanField('Remember me', render_kw={"placeholder": "Remember me"})

    submit = SubmitField('Login')