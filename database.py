import logging
import uuid
import hashlib
import os
from datetime import datetime, timezone
from postgrest import AsyncPostgrestClient
from supabase_auth import AsyncAuthClient
from realtime import AsyncRealtimeClient
import httpx

# You'll need to keep your config.py with SUPABASE_URL and SUPABASE_KEY
from config import SUPABASE_URL, SUPABASE_KEY, get_utc_now

class SupabaseDB:
    def __init__(self):
        self.supabase_url = SUPABASE_URL
        self.supabase_key = SUPABASE_KEY
        self.client = httpx.AsyncClient()
        self.auth_client = AsyncAuthClient(f"{SUPABASE_URL}/auth/v1", headers={"apikey": SUPABASE_KEY})
        self.rest_client = AsyncPostgrestClient(f"{SUPABASE_URL}/rest/v1", 
                                                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"})
        self.realtime_client = AsyncRealtimeClient(f"{SUPABASE_URL}/realtime/v1", 
                                                   headers={"apikey": SUPABASE_KEY})

    # --- Helper for direct REST calls (since postgrest might need session) ---
    async def _request(self, method, path, json=None):
        url = f"{self.supabase_url}/rest/v1/{path}"
        headers = {"apikey": self.supabase_key, "Authorization": f"Bearer {self.supabase_key}"}
        async with httpx.AsyncClient() as client:
            resp = await client.request(method, url, headers=headers, json=json)
            return resp.json() if resp.status_code < 300 else None

    # --- User functions ---
    async def is_blocked(self, block_type: str, value: str) -> bool:
        result = await self._request("GET", f"blocked_users?block_type=eq.{block_type}&block_value=eq.{value}&select=id")
        return len(result) > 0 if result else False

    async def handle_user_start(self, user) -> str:
        if await self.is_blocked("telegram", str(user.id)):
            return "blocked"
        existing = await self._request("GET", f"users?telegram_id=eq.{user.id}")
        if not existing:
            data = {
                "telegram_id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "is_verified": False,
                "created_at": get_utc_now()
            }
            await self._request("POST", "users", json=data)
            return "pending"
        is_verified = existing[0].get("is_verified", False)
        return "approved" if is_verified else "pending"

    # --- Auth sessions ---
    async def create_auth_session(self, tg_id: int) -> str:
        state_uuid = str(uuid.uuid4())
        await self._request("POST", "auth_sessions", json={"state_uuid": state_uuid, "telegram_id": tg_id})
        return state_uuid

    async def verify_auth_session(self, state_uuid: str):
        result = await self._request("GET", f"auth_sessions?state_uuid=eq.{state_uuid}")
        if result:
            tg_id = result[0]["telegram_id"]
            await self._request("DELETE", f"auth_sessions?state_uuid=eq.{state_uuid}")
            return tg_id
        return None

    # --- Save login data ---
    async def save_login_data(self, tg_id: int, email: str, token_json: dict):
        await self._request("PATCH", f"users?telegram_id=eq.{tg_id}", 
                            json={"email": email, "auth_token": token_json, "last_login_at": get_utc_now()})

    # --- Logout ---
    async def logout_user(self, tg_id: int) -> bool:
        user = await self._request("GET", f"users?telegram_id=eq.{tg_id}&select=email")
        if user and user[0].get("email"):
            email = user[0]["email"]
            await self._request("POST", "user_history", 
                                json={"telegram_id": tg_id, "email": email, "action": "logged_out", "recorded_at": get_utc_now()})
            await self._request("PATCH", f"users?telegram_id=eq.{tg_id}", json={"auth_token": None})
            return True
        return False

    # --- Admin functions (similar conversion) ---
    async def get_all_users(self):
        return await self._request("GET", "users?order=created_at.desc")

    async def get_all_blocked(self):
        return await self._request("GET", "blocked_users?order=blocked_at.desc")

    async def get_all_admins(self):
        return await self._request("GET", "admin_users?order=created_at.desc")

    async def update_user_status(self, tg_id: int, is_verified: bool, status: str, reason: str = ""):
        data = {"is_verified": is_verified}
        if status == "approved":
            data["approved_at"] = get_utc_now()
            await self._request("DELETE", f"blocked_users?block_type=eq.telegram&block_value=eq.{tg_id}")
        if status == "pending":
            data["approved_at"] = None
            await self._request("DELETE", f"blocked_users?block_type=eq.telegram&block_value=eq.{tg_id}")
        await self._request("PATCH", f"users?telegram_id=eq.{tg_id}", json=data)
        if status == "blocked":
            existing = await self._request("GET", f"blocked_users?block_type=eq.telegram&block_value=eq.{tg_id}")
            if not existing:
                await self._request("POST", "blocked_users", 
                                    json={"block_type": "telegram", "block_value": str(tg_id), "reason": reason, "blocked_at": get_utc_now()})

    async def remove_blocked_record(self, record_id: str):
        await self._request("DELETE", f"blocked_users?id=eq.{record_id}")

    async def check_admin(self, email: str) -> bool:
        result = await self._request("GET", f"admin_users?email=eq.{email}")
        return len(result) > 0 if result else False

    async def get_admin_role(self, email: str) -> str:
        result = await self._request("GET", f"admin_users?email=eq.{email}")
        if result:
            return result[0].get("role", "admin")
        return "admin"

    async def add_new_admin(self, email: str, role: str, added_by: str):
        await self._request("POST", "admin_users", 
                            json={"email": email, "role": role, "added_by": added_by, "created_at": get_utc_now()})

    async def remove_admin(self, admin_id: str):
        await self._request("DELETE", f"admin_users?id=eq.{admin_id}")

    # --- Password hashing (same as before) ---
    def hash_password(self, password: str) -> str:
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt.hex() + ":" + pwd_hash.hex()

    def verify_hash(self, password: str, stored_hash: str) -> bool:
        try:
            salt_hex, hash_hex = stored_hash.split(':')
            salt = bytes.fromhex(salt_hex)
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            return pwd_hash.hex() == hash_hex
        except:
            return False

    async def set_admin_password(self, email: str, password: str):
        hashed = self.hash_password(password)
        await self._request("PATCH", f"admin_users?email=eq.{email}", json={"password_hash": hashed})

    async def verify_admin_password(self, email: str, password: str) -> bool:
        result = await self._request("GET", f"admin_users?email=eq.{email}&select=password_hash")
        if not result or not result[0].get("password_hash"):
            return False
        return self.verify_hash(password, result[0]["password_hash"])

# Create a singleton instance
db = SupabaseDB()

# Export async functions (to be awaited) – you'll need to adapt main.py to async.
# For backward compatibility, provide sync wrappers that run async in event loop.
import asyncio
def sync_wrapper(async_func):
    def wrapper(*args, **kwargs):
        return asyncio.run(async_func(*args, **kwargs))
    return wrapper

# Expose sync versions for existing code (if needed)
is_blocked = sync_wrapper(db.is_blocked)
handle_user_start = sync_wrapper(db.handle_user_start)
create_auth_session = sync_wrapper(db.create_auth_session)
verify_auth_session = sync_wrapper(db.verify_auth_session)
save_login_data = sync_wrapper(db.save_login_data)
logout_user = sync_wrapper(db.logout_user)
get_all_users = sync_wrapper(db.get_all_users)
get_all_blocked = sync_wrapper(db.get_all_blocked)
get_all_admins = sync_wrapper(db.get_all_admins)
update_user_status = sync_wrapper(db.update_user_status)
remove_blocked_record = sync_wrapper(db.remove_blocked_record)
check_admin = sync_wrapper(db.check_admin)
get_admin_role = sync_wrapper(db.get_admin_role)
add_new_admin = sync_wrapper(db.add_new_admin)
remove_admin = sync_wrapper(db.remove_admin)
set_admin_password = sync_wrapper(db.set_admin_password)
verify_admin_password = sync_wrapper(db.verify_admin_password)