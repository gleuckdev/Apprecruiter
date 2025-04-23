# main.py
import os
from app import create_app

# Create the Flask application instance
app = create_app()

# This file is used as the entry point for the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)