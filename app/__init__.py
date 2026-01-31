from flask import Flask
from app.models import db
from app.web.routes import web
import os

from dotenv import load_dotenv

load_dotenv()

def create_app():
    app = Flask(__name__, 
                template_folder='web/templates',
                static_folder='web/static')
    
    # Config
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///spectra.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-fallback')
    app.config['GITHUB_PAT'] = os.environ.get('GITHUB_PAT')

    # Init DB
    db.init_app(app)
    
    # Init Scheduler
    from app.scheduler import init_scheduler
    init_scheduler(app)
    
    # Register Blueprints
    app.register_blueprint(web)
    
    # Create Tables
    with app.app_context():
        db.create_all()
        
    return app
