import os

class Config:
    # General Configurations
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')  # Replace with a secure key in production
    DEBUG = os.environ.get('FLASK_DEBUG', 'False') == 'True'

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disables modification tracking to save resources
    SQLALCHEMY_ECHO = False  # Set to True for verbose SQL logging during development
