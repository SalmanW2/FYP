from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from config import BOT_TOKEN, RENDER_URL
from database import handle_user_start
from auth import get_login_url
import logging

ptb_app = Application.builder().token(BOT_TOKEN).build()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    status = handle_user_start(user)
    if status == "blocked":
        await update.message.reply_text("⛔ Sorry, your access to this bot has been restricted. You are blocked.")
    elif status == "pending":
        await update.message.reply_text("⏳ Your access request has been sent to the administrator. Please wait for approval.")
    elif status == "approved":
        auth_url = get_login_url(user.id)
        await update.message.reply_text(f"✅ Welcome! Please link your Google account:\n{auth_url}")

ptb_app.add_handler(CommandHandler("start", start_command))

app = FastAPI()

@app.post(f"/{BOT_TOKEN}")
async def telegram_webhook(request: Request):
    data = await request.json()
    await ptb_app.process_update(Update.de_json(data, ptb_app.bot))
    return {"status": "ok"}

@app.get("/callback")
async def google_callback(request: Request):
    from auth import process_callback
    code = request.query_params.get("code")
    state_uuid = request.query_params.get("state")
    if not code or not state_uuid:
        return RedirectResponse(url="/callback_success?msg=Invalid Request&success=false")
    status_type, result_data = process_callback(code, state_uuid)
    if status_type == "admin":
        response = RedirectResponse(url="/admin/dashboard", status_code=302)
        response.set_cookie(key="admin_session", value=result_data, max_age=86400)
        return response
    elif status_type == "error" and "Admin" in result_data:
        return RedirectResponse(url=f"/callback_success?msg={result_data}&success=false&is_admin_error=true")
    elif status_type == "user":
        return RedirectResponse(url=f"/callback_success?msg={result_data}&success=true")
    else:
        return RedirectResponse(url=f"/callback_success?msg={result_data}&success=false")

@app.get("/")
def root():
    return {"message": "Smart Email Assistant is running!"}