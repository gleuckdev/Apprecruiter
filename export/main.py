# main.py
import os
from app import create_app

# Create the Flask application instance
app = create_app()

# This file is used as the entry point for the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Use Render's dynamic port
    app.run(host='0.0.0.0', port=port)
