import sys
import os

# Add application directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Activate virtual environment if it exists
venv_activate = os.path.join(os.path.dirname(__file__), 'venv/bin/activate_this.py')
if os.path.exists(venv_activate):
    with open(venv_activate) as f:
        exec(f.read(), {'__file__': venv_activate})

# Load environment variables from .env (optional in production)
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    # python-dotenv not installed, use environment variables directly
    pass

# Import Flask application
from app import app as application

# Create tables on startup (only if they don't exist)
with application.app_context():
    try:
        from models import db
        # Check if tables exist before creating
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        if not existing_tables:
            db.create_all()
            print("✅ Database tables initialized successfully")
        else:
            print(f"✅ Database ready ({len(existing_tables)} tables exist)")
    except Exception as e:
        # Silently handle if tables already exist
        if "already exists" not in str(e):
            print(f"⚠️ Database initialization note: {e}")

# WSGI entry point for LiteSpeed
if __name__ == '__main__':
    application.run()
