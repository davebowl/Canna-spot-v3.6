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
try:
    from app import app as application
    print("✅ Flask app imported successfully")
except Exception as e:
    print(f"❌ Failed to import Flask app: {e}")
    import traceback
    traceback.print_exc()
    raise

# Create tables on startup - wrapped in try/except to not block startup
try:
    with application.app_context():
        from models import db
        db.create_all()
        print("✅ Database tables created/verified")
except Exception as e:
    print(f"⚠️ Database setup warning (app will still run): {e}")
    # Don't crash - let the app start even if DB has issues

# WSGI entry point for LiteSpeed
if __name__ == '__main__':
    application.run()

