from flask import current_app

def with_app_context(func):
    """A decorator to push the Flask app context to threaded functions."""
    def wrapper(*args, **kwargs):
        with current_app.app_context():
            return func(*args, **kwargs)
    return wrapper