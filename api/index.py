import sys
from pathlib import Path

# Ensure backend directory is in sys.path for serverless resolution
root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import app

# Expose app for Vercel ASGI
app = app
