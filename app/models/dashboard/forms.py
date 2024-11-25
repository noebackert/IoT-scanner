# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Create forms to be passed to the frontend
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, TimeField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange


class sliderGlobalDataRate(FlaskForm):
    slider = IntegerField('Slider', validators=[DataRequired(), NumberRange(min=1, max=1000)], default=1, render_kw={'placeholder': 'In seconds'})
    
    def get_slider_range(self):
        """Return the min and max values of the slider"""
        for validator in self.slider.validators:
            if isinstance(validator, NumberRange):
                return validator.min, validator.max
    