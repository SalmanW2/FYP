import logging
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from config import RENDER_URL, SCOPES
from database import create_auth_session, verify_auth_session, save_login_data, is_blocked, check_admin
import os
import json

def get_credentials_path():
    if os.path.exists('/etc/secrets/credentials.json'):
        return '/etc/secrets/credentials.json'
    return 'credentials.json'

oauth_sessions = {}

def get_login_url(tg_id: int):
    state_uuid = create_auth_session(tg_id)
    flow = Flow.from_client_secrets_file(
        get_credentials_path(),
        scopes=SCOPES,
        redirect_uri=f"{RENDER_URL}/callback"
    )
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline', state=state_uuid)
    oauth_sessions[state_uuid] = flow
    return auth_url

def get_admin_login_url():
    state_uuid = create_auth_session(0)
    flow = Flow.from_client_secrets_file(
        get_credentials_path(),
        scopes=SCOPES,
        redirect_uri=f"{RENDER_URL}/callback"
    )
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline', state=state_uuid)
    oauth_sessions[state_uuid] = flow
    return auth_url

def process_callback(code: str, state_uuid: str):
    tg_id = verify_auth_session(state_uuid)
    if tg_id is None:
        return "error", "Security Error: Session expired or invalid CSRF token."
    
    flow = oauth_sessions.get(state_uuid)
    if not flow:
        return "error", "Session expired. Please try logging in again."
    
    try:
        flow.fetch_token(code=code)
        creds = flow.credentials
        user_info_service = build('oauth2', 'v2', credentials=creds)
        user_info = user_info_service.userinfo().get().execute()
        email = user_info.get("email")
        
        if state_uuid in oauth_sessions:
            del oauth_sessions[state_uuid]
        
        if tg_id == 0:
            if check_admin(email):
                return "admin", email
            else:
                return "error", "Access Denied: You are not authorized as an Administrator."
        
        if is_blocked("email", email):
            return "error", "Access Denied: This email address has been blacklisted."
        
        token_json = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes
        }
        
        save_login_data(tg_id, email, token_json)
        return "user", "Success! Your account has been successfully linked."
    
    except Exception as e:
        logging.error(f"Auth Error: {e}")
        return "error", f"Authentication failed: {e}"