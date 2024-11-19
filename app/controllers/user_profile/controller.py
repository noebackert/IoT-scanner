# This file is part of PyFlaSQL.
# Original author: Noé Backert (noe.backert@gmail.com)
# License: check the LICENSE file.
"""
Business logic for user profile
"""
from flask import Flask, render_template, url_for, redirect, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from ...models.user_profile.forms import changePassword
from ...models.sql import db, UserDB
from ...controllers.controller import get_bcrypt
from functools import wraps


@login_required
def user_profile():
    """
        Control the logout page.
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - redirect to login page
        """
    username = current_user.username
    return render_template(url_for('blueprint.user_profile')+'.html', username=username)

@login_required
def modify_password():
    """
        Control the logout page.
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - redirect to login page
        """
    content = {
        "form" : changePassword()
    }
    bcrypt = get_bcrypt()
    if content['form'].validate_on_submit():
        if current_user:
            if bcrypt.check_password_hash(current_user.password, content['form'].oldPassword.data):
                if content['form'].newPassword.data == content['form'].confirmPassword.data:
                    current_user.password = bcrypt.generate_password_hash(content['form'].newPassword.data).decode('utf-8')
                    db.session.commit()
                    flash('Password changed successfully! Please Login again', 'Success')
                    return redirect(url_for('blueprint.login'))
                else:
                    flash('Passwords do not match!', 'Error')
                    redirect(url_for('blueprint.modify_password'))
            else:
                flash('Old password incorrect!', 'Error')
                redirect(url_for('blueprint.modify_password'))
        else:
            flash('User not found!', 'Error')
            redirect(url_for('blueprint.modify_password'))
    return render_template(url_for('blueprint.modify_password')+'.html', content=content, username=current_user.username)