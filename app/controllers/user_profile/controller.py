# This file is part of PyFlaSQL.
# Original author: Raphael Viera (raphael.viera@emse.fr)
# Contribution : ISMIN student X (ismin.student@etu.emse.fr)
# License: check the LICENSE file.
"""
Business logic for user profile
"""
from flask import Flask, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from ...models.sql import db, UserDB

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
