"""
    Run the main application.
"""
from app import PyFlaSQL

if __name__ == "__main__":
    PyFlaSQL.run(host="0.0.0.0", port=5000 ,debug=True)
