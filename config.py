import os
from dotenv import load_dotenv, find_dotenv


# Load environment variables from .env file
load_dotenv(find_dotenv())


# API Keys (no default fallbacks - a missing key must stay missing)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
IPINFO_ACCESS_TOKEN = os.getenv("IPINFO_ACCESS_TOKEN")


# Flask Configuration
class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv("SECRET_KEY")

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
