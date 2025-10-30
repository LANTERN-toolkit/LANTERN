# /config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration settings for the Flask application."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_very_secret_default_key')
    GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')