# /app/__init__.py
import os
import time
from flask import Flask
from config import Config

def create_app(config_class=Config):
    """Creates and configures the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Import and register routes
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    # Clean up old temporary files on startup
    cleanup_old_temp_files()
    
    return app

def cleanup_old_temp_files():
    """Clean up temporary files older than 1 hour."""
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'temp')
    if not os.path.exists(temp_dir):
        return
    
    current_time = time.time()
    for filename in os.listdir(temp_dir):
        if filename.startswith('script_') and filename.endswith('.json'):
            file_path = os.path.join(temp_dir, filename)
            file_age = current_time - os.path.getmtime(file_path)
            # Remove files older than 1 hour (3600 seconds)
            if file_age > 3600:
                try:
                    os.remove(file_path)
                    print(f"Cleaned up old temp file: {filename}")
                except OSError:
                    pass  # File might have been removed already