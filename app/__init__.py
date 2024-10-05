from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

# Initialize the database
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'supersecretkey'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secfile.db'

    db.init_app(app)

    # Initialize Login Manager
    
    login_manager.login_view = 'main.login'
    login_manager.init_app(app)

    # Import models
    from .models import User, File, Backup, FileAccess, RecoveryRequest

    # Import routes
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Database migration
    migrate = Migrate(app, db)

    return app
