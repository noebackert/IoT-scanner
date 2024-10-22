"""
Configure database path, secret key, and debug mode.
"""
import os


SECRET_KEY = os.getenv('SECRET_KEY')
basedir = os.path.abspath(os.path.dirname(__file__))
DEVELOPMENT = os.getenv('DEVELOPMENT', True)
DEBUG = os.getenv('DEBUG', True)
FLASK_ENV=os.getenv('FLASK_ENV', 'development')
FLASK_APP=os.getenv('FLASK_APP', "app.py")

# Connect to the MYSQL database
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')

# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = False

