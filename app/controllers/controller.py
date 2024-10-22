"""
Business logic for the main application
"""
from flask import Flask, render_template, url_for, redirect, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

from ..models.app import PyFlaSQL
from ..models.sql import db, UserDB
from ..models.auth import LoginForm, RegisterForm

def get_bcrypt():
    pyflasql_obj = PyFlaSQL()
    bcrypt = Bcrypt(pyflasql_obj.myapp)
    return bcrypt

def index():
    """
        Handles the logic for / (home page)

        Args:
            - None.

        Returns:
            - rendered index.html template
        """

    return render_template('index.html')

def login():
    """
        Handles the logic for /login page

        Args:
            - None.

        Returns:
            - rendered .html template (dashboard.html if login success or login.html if login fail)
        """
    bcrypt = get_bcrypt()
    form = LoginForm()
    if form.validate_on_submit():
        user = UserDB.query.filter_by(username=form.username.data).first()
        remember_me = True if form.remember_me.data else False
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=remember_me)
                return redirect(url_for('blueprint.dashboard'))
        flash('Login or password incorrect!', 'Error')
    return render_template('login.html', form=form)

@login_required
def dashboard():
    """
        Handles the logic for /dashboard page
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - rendered dashboard.html template
        """
    username = current_user.username
    return render_template('dashboard.html', username=username)

@login_required
def about():
    """
        Handles the logic for /dashboard page
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - rendered dashboard.html template
        """
    username = current_user.username
    return render_template('about.html', username=username)

@login_required
def logout():
    """
        Handles the logic for /logout page
        Login is required to view this page.

        Args:
            - None.

        Returns:
            - redirect to login page
        """
    logout_user()
    return redirect(url_for('blueprint.login'))

def register():
    """
        Handles the logic for /register page

        Args:
            - None.

        Returns:
            - rendered .html template
        """
    bcrypt = get_bcrypt()
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(form.password.data)
        print(hashed_password)

        new_user = UserDB(username=form.username.data, password=hashed_password, role=999)
        db.session.add(new_user)
        db.session.commit()
        
        # test password
        user = UserDB.query.filter_by(username=form.username.data).first()
        print(user.password)
        
        return redirect(url_for('blueprint.login'))
    

    return render_template('register.html', form=form)