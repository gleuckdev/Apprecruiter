from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    # Load config
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Debugging step
    print("Loaded DB URI:", app.config['SQLALCHEMY_DATABASE_URI'])

    # Initialize DB
    db.init_app(app)

    # Register blueprints or routes
    # from .views import views
    # app.register_blueprint(views)

    return app
