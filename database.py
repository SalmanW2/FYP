import logging
import uuid
import hashlib
import os
import requests
from config import SUPABASE_URL, SUPABASE_KEY, get_utc_now

SUPABASE_URL = SUPABASE_URL.rstrip('/')
HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json"
}

def _request(method, path, json=None):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    resp = requests.request(method, url, headers=HEADERS, json=json)
    if resp.status_code >= 400:
        logging.error(f"Supabase error {resp.status_code}: {resp.text}")
        return None
    return resp.json() if resp.content else None

def is_blocked(block_type, value):
    result = _request("GET", f"blocked_users?block_type=eq.{block_type}&block_value=eq.{value}&select=id")
    return len(result) > 0 if result else False

def handle_user_start(user):
    if is_blocked("telegram", str(user.id)):
        return "blocked"
    existing = _request("GET", f"users?telegram_id=eq.{user.id}")
    if not existing:
        data = {
            "telegram_id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "is_verified": False,
            "created_at": get_utc_now()
        }
        _request("POST", "users", json=data)
        return "pending"
    is_verified = existing[0].get("is_verified", False)
    return "approved" if is_verified else "pending"

def create_auth_session(tg_id):
    state_uuid = str(uuid.uuid4())
    _request("POST", "auth_sessions", json={"state_uuid": state_uuid, "telegram_id": tg_id})
    return state_uuid

def verify_auth_session(state_uuid):
    result = _request("GET", f"auth_sessions?state_uuid=eq.{state_uuid}")
    if result:
        tg_id = result[0]["telegram_id"]
        _request("DELETE", f"auth_sessions?state_uuid=eq.{state_uuid}")
        return tg_id
    return None

def save_login_data(tg_id, email, token_json):
    _request("PATCH", f"users?telegram_id=eq.{tg_id}", 
             json={"email": email, "auth_token": token_json, "last_login_at": get_utc_now()})

def logout_user(tg_id):
    user = _request("GET", f"users?telegram_id=eq.{tg_id}&select=email")
    if user and user[0].get("email"):
        email = user[0]["email"]
        _request("POST", "user_history", 
                 json={"telegram_id": tg_id, "email": email, "action": "logged_out", "recorded_at": get_utc_now()})
        _request("PATCH", f"users?telegram_id=eq.{tg_id}", json={"auth_token": None})
        return True
    return False

def get_all_users():
    return _request("GET", "users?order=created_at.desc") or []

def get_all_blocked():
    return _request("GET", "blocked_users?order=blocked_at.desc") or []

def get_all_admins():
    return _request("GET", "admin_users?order=created_at.desc") or []

def update_user_status(tg_id, is_verified, status, reason=""):
    data = {"is_verified": is_verified}
    if status == "approved":
        data["approved_at"] = get_utc_now()
        _request("DELETE", f"blocked_users?block_type=eq.telegram&block_value=eq.{tg_id}")
    if status == "pending":
        data["approved_at"] = None
        _request("DELETE", f"blocked_users?block_type=eq.telegram&block_value=eq.{tg_id}")
    _request("PATCH", f"users?telegram_id=eq.{tg_id}", json=data)
    if status == "blocked":
        existing = _request("GET", f"blocked_users?block_type=eq.telegram&block_value=eq.{tg_id}")
        if not existing:
            _request("POST", "blocked_users", 
                     json={"block_type": "telegram", "block_value": str(tg_id), "reason": reason, "blocked_at": get_utc_now()})

def remove_blocked_record(record_id):
    _request("DELETE", f"blocked_users?id=eq.{record_id}")

def check_admin(email):
    result = _request("GET", f"admin_users?email=eq.{email}")
    return len(result) > 0 if result else False

def get_admin_role(email):
    result = _request("GET", f"admin_users?email=eq.{email}")
    if result:
        return result[0].get("role", "admin")
    return "admin"

def add_new_admin(email, role, added_by):
    _request("POST", "admin_users", 
             json={"email": email, "role": role, "added_by": added_by, "created_at": get_utc_now()})

def remove_admin(admin_id):
    _request("DELETE", f"admin_users?id=eq.{admin_id}")

def hash_password(password):
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_hash(password, stored_hash):
    try:
        salt_hex, hash_hex = stored_hash.split(':')
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return pwd_hash.hex() == hash_hex
    except:
        return False

def set_admin_password(email, password):
    hashed = hash_password(password)
    _request("PATCH", f"admin_users?email=eq.{email}", json={"password_hash": hashed})

def verify_admin_password(email, password):
    result = _request("GET", f"admin_users?email=eq.{email}&select=password_hash")
    if not result or not result[0].get("password_hash"):
        return False
    return verify_hash(password, result[0]["password_hash"])