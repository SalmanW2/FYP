import os
from datetime import datetime, timezone

BOT_TOKEN = os.getenv("BOT_TOKEN")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
RENDER_URL = os.getenv("RENDER_EXTERNAL_URL", "https://your-app.onrender.com")

SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid'
]

def get_utc_now():
    return datetime.now(timezone.utc).isoformat()