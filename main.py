from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from contextlib import asynccontextmanager
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    webhook_url = f"{RENDER_URL}/{BOT_TOKEN}"
    await ptb_app.bot.set_webhook(url=webhook_url)
    logging.info(f"Webhook set to {webhook_url}")
    
    await ptb_app.initialize()  # Added: Required before start()
    await ptb_app.start()
    
    yield
    
    await ptb_app.stop()
    await ptb_app.shutdown()    # Added: Clean cleanup

app = FastAPI(lifespan=lifespan)

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

@app.get("/", response_class=HTMLResponse)
def root():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Smart Email Assistant</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #0f172a;
                color: #e2e8f0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                text-align: center;
                background: #1e293b;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            }
            h1 { color: #38bdf8; margin-bottom: 10px; }
            p { font-size: 1.1em; color: #94a3b8; }
            .status {
                display: inline-block;
                margin-top: 20px;
                padding: 8px 15px;
                background-color: #22c55e;
                color: white;
                border-radius: 20px;
                font-weight: bold;
                font-size: 0.9em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🤖 Smart Email Assistant</h1>
            <p>Your Agentic AI backend is active and listening.</p>
            <div class="status">● System Online</div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)