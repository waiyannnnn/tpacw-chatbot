"""The chatbot's main program. Beginner instructions are in the Markdown guide.

EDIT YOUR ANSWERS IN responses.json, NOT IN THIS FILE.
Secrets are in .env, NOT in responses.json.
"""

# ========== PART 1: TOOLS THE CHATBOT USES ==========
# These come with Python, except FastAPI, requests and python-dotenv.
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

# Choose where questions and chat history are saved.
DB_PATH = Path(os.getenv("DB_PATH") or (ROOT / "chatbot.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# These details must be chosen by the business owner in .env.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
MODE = os.getenv("NOTIFY_MODE", "dashboard").strip().lower()

# These values are used only when their corresponding messaging option is enabled.
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT = os.getenv("TELEGRAM_OWNER_CHAT_ID", "").strip()
WA_ACCESS_TOKEN = os.getenv("WA_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WA_PHONE_NUMBER_ID", "").strip()
WA_OWNER_PHONE = re.sub(r"\D", "", os.getenv("WA_OWNER_PHONE", ""))
WA_TEMPLATE_NAME = os.getenv("WA_TEMPLATE_NAME", "new_website_question").strip()
WA_TEMPLATE_LANGUAGE = os.getenv("WA_TEMPLATE_LANGUAGE", "en_US").strip()
WA_VERIFY_TOKEN = os.getenv("WA_VERIFY_TOKEN", "").strip()
WA_APP_SECRET = os.getenv("WA_APP_SECRET", "").strip()
WA_GRAPH_VERSION = os.getenv("WA_GRAPH_VERSION", "v23.0").strip()

if not ADMIN_USERNAME or not ADMIN_PASSWORD or ADMIN_PASSWORD.startswith("REPLACE_WITH_"):
    raise RuntimeError("Open .env and set your own ADMIN_USERNAME and ADMIN_PASSWORD first. See Chapter 4.")
if MODE not in {"dashboard", "telegram", "whatsapp"}:
    raise RuntimeError("NOTIFY_MODE must be dashboard, telegram or whatsapp in .env.")
if MODE == "telegram" and not (TELEGRAM_TOKEN and TELEGRAM_CHAT):
    raise RuntimeError("Telegram mode needs TELEGRAM_BOT_TOKEN and TELEGRAM_OWNER_CHAT_ID in .env.")
if MODE == "whatsapp" and not all([
    WA_ACCESS_TOKEN, WA_PHONE_NUMBER_ID, WA_OWNER_PHONE, WA_VERIFY_TOKEN, WA_APP_SECRET
]):
    raise RuntimeError("WhatsApp mode needs all WA_ settings in .env. Read Chapter 11.")

app = FastAPI(title="Beginner Website Chatbot")
security = HTTPBasic()

# ========== PART 2: THE CHATBOT'S DATABASE ==========
# SQLite saves messages in a single file on your computer.
# Every visitor has a random conversation key; their messages stay separate.

_db_lock = threading.RLock()


def open_db():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=15000")
    return db


def setup_db():
    with _db_lock, closing(open_db()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                question TEXT NOT NULL,
                answer TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                answered_at TEXT,
                notice_status TEXT NOT NULL DEFAULT 'waiting'
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                question_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_chat_messages ON messages (chat_id, id);
            CREATE TABLE IF NOT EXISTS received_whatsapp (
                message_id TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS telegram_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                next_update INTEGER NOT NULL DEFAULT 0
            );
        """)
        db.commit()


setup_db()

# ========== PART 3: CHECK SAVED QUESTIONS AND ANSWERS ==========
# CUSTOMISE responses.json, NOT this part of the program.


def business_settings():
    # Reading the file each time means edited answers are available immediately.
    try:
        with (ROOT / "responses.json").open("r", encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data["responses"], list):
            raise ValueError("responses must be a list")
        return data
    except (OSError, ValueError, KeyError) as error:
        raise RuntimeError(f"Fix responses.json: {error}") from error


def find_answer(question, settings):
    # Search for full words or phrases, ignoring upper/lowercase differences.
    # The LONGEST matching phrase wins if several phrases match.
    question = " ".join(question.casefold().split())
    best = None
    best_length = 0
    for saved_item in settings["responses"]:
        for keyword in saved_item.get("keywords", []):
            keyword = " ".join(keyword.casefold().split())
            if not keyword:
                continue
            pattern = r"(?<!\w)" + re.escape(keyword) + r"(?!\w)"
            if re.search(pattern, question) and len(keyword) > best_length:
                best_length = len(keyword)
                best = saved_item["answer"]
    if best is None:
        return None
    # Replace placeholders such as {opening_hours} with the owner's details.
    for key, value in settings["business"].items():
        best = best.replace("{" + key + "}", str(value))
    return best


# ========== PART 4: PROTECT THE OWNER'S PAGE ==========
# The browser asks for a username/password before opening the owner's page.
# Never enter this password on a shared, untrusted computer.


def owner_login(credentials: HTTPBasicCredentials = Depends(security)):
    valid_username = secrets.compare_digest(credentials.username.encode(), ADMIN_USERNAME.encode())
    valid_password = secrets.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())
    if not (valid_username and valid_password):
        raise HTTPException(401, "Incorrect owner login.", headers={"WWW-Authenticate": "Basic"})
    return True


# ========== PART 5: BASIC PROTECTION AGAINST MESSAGE SPAM ==========
# Allow at most 12 new messages from an address in 60 seconds.
# This is a simple starter safeguard, NOT a full production security system.
_rate_lock = threading.Lock()
_rate_hits = defaultdict(deque)


def check_message_limit(address):
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[address]
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= 12:
            raise HTTPException(429, "Too many messages. Please try again in one minute.")
        hits.append(now)


class CustomerQuestion(BaseModel):
    chat_id: str = Field(min_length=32, max_length=100, pattern=r"^[a-f0-9-]+$")
    text: str = Field(min_length=1, max_length=1000)


class OwnerAnswer(BaseModel):
    answer: str = Field(min_length=1, max_length=2000)


# ========== PART 6: CUSTOMER WEBSITE AND CHAT HISTORY ==========


@app.get("/")
def customer_website():
    return FileResponse(ROOT / "website" / "index.html")


@app.get("/owner")
def owner_website(_=Depends(owner_login)):
    return FileResponse(ROOT / "website" / "owner.html")


@app.get("/api/settings")
def get_settings():
    settings = business_settings()
    return {
        "business_name": settings["business"]["name"],
        "welcome_message": settings["chatbot"]["welcome_message"],
        "unanswered_message": settings["chatbot"]["unanswered_message"]
    }


@app.get("/api/history/{chat_id}")
def get_history(chat_id: str, after: int = Query(default=0, ge=0)):
    # The chat ID is a secret, random key generated by the visitor's browser.
    # This is suitable for a basic low-risk demonstration, not sensitive records.
    if not re.fullmatch(r"[a-f0-9-]{32,100}", chat_id):
        raise HTTPException(400, "Invalid conversation ID")
    with closing(open_db()) as db:
        rows = db.execute("""
            SELECT id, sender, text, created_at
            FROM messages WHERE chat_id = ? AND id > ?
            ORDER BY id LIMIT 100
        """, (chat_id, after)).fetchall()
    return [dict(row) for row in rows]


# ========== PART 7: HANDLE CUSTOMER QUESTIONS ==========
# Everything gets saved BEFORE an external messaging service is contacted.


@app.post("/api/message")
def handle_question(message: CustomerQuestion, request: Request):
    check_message_limit(request.client.host if request.client else "unknown")
    text = message.text.strip()
    if not text:
        raise HTTPException(400, "Please type a question.")
    settings = business_settings()
    automatic_answer = find_answer(text, settings)

    with _db_lock, closing(open_db()) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO messages (chat_id, sender, text) VALUES (?, 'customer', ?)",
            (message.chat_id, text)
        )
        question_id = None
        if automatic_answer is None:
            cursor = db.execute(
                "INSERT INTO questions (chat_id, question) VALUES (?, ?)",
                (message.chat_id, text)
            )
            question_id = cursor.lastrowid
            answer = settings["chatbot"]["unanswered_message"]
        else:
            answer = automatic_answer
        db.execute(
            "INSERT INTO messages (chat_id, sender, text, question_id) VALUES (?, 'bot', ?, ?)",
            (message.chat_id, answer, question_id)
        )
        db.commit()

    # Notify the owner only when the chatbot could not answer.
    if question_id is not None:
        status = notify_owner(question_id, text)
        with _db_lock, closing(open_db()) as db:
            db.execute("UPDATE questions SET notice_status = ? WHERE id = ?", (status, question_id))
            db.commit()
    return {"accepted": True, "question_id": question_id}


# ========== PART 8: THE OWNER'S UNANSWERED QUESTIONS PAGE ==========


@app.get("/api/owner/questions")
def owner_questions(_=Depends(owner_login)):
    with closing(open_db()) as db:
        rows = db.execute("""
            SELECT id, question, created_at, notice_status
            FROM questions WHERE answer IS NULL ORDER BY id DESC LIMIT 200
        """).fetchall()
    return [dict(row) for row in rows]


def save_owner_answer(question_id, answer):
    # This one place is shared by the owner's page, Telegram and WhatsApp.
    answer = answer.strip()
    if not answer or len(answer) > 2000:
        return False
    with _db_lock, closing(open_db()) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT chat_id FROM questions WHERE id = ? AND answer IS NULL", (question_id,)
        ).fetchone()
        if row is None:
            db.rollback()
            return False
        db.execute("""
            UPDATE questions SET answer = ?, answered_at = CURRENT_TIMESTAMP
            WHERE id = ? AND answer IS NULL
        """, (answer, question_id))
        db.execute(
            "INSERT INTO messages (chat_id, sender, text, question_id) VALUES (?, 'owner', ?, ?)",
            (row["chat_id"], answer, question_id)
        )
        db.commit()
    return True


@app.post("/api/owner/reply/{question_id}")
def owner_reply(question_id: int, reply: OwnerAnswer, _=Depends(owner_login)):
    if not save_owner_answer(question_id, reply.answer):
        raise HTTPException(404, "Question not found or already answered.")
    return {"success": True}


# ========== PART 9: CHOOSE HOW THE OWNER GETS NOTIFIED ==========
# dashboard: free; owner checks the password-protected web page.
# telegram: free standard Telegram Bot API, plus a second Python program.
# whatsapp: official Meta Cloud API, possible per-message charges.


def notify_owner(question_id, question):
    if MODE == "dashboard":
        return "dashboard_only"

    if MODE == "telegram":
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT,
            "text": f"Website question #{question_id}:\n{question}\n\nReply with: #{question_id} your answer"
        }
    else:
        # IMPORTANT: WhatsApp usually requires an APPROVED message template
        # to initiate a conversation with the owner. Meta may charge for it.
        url = f"https://graph.facebook.com/{WA_GRAPH_VERSION}/{WA_PHONE_NUMBER_ID}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to": WA_OWNER_PHONE,
            "type": "template",
            "template": {
                "name": WA_TEMPLATE_NAME,
                "language": {"code": WA_TEMPLATE_LANGUAGE},
                "components": [{
                    "type": "body",
                    "parameters": [
                        {"type": "text", "text": str(question_id)},
                        {"type": "text", "text": question[:500]}
                    ]
                }]
            }
        }

    headers = {"Authorization": f"Bearer {WA_ACCESS_TOKEN}"} if MODE == "whatsapp" else {}
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        if MODE == "telegram" and not response.json().get("ok"):
            return "failed_check_owner_page"
        return "sent"
    except (requests.RequestException, ValueError) as error:
        # We DO NOT lose the customer's question when an outside service fails.
        print(f"Owner notice failed for #{question_id}: {type(error).__name__}")
        return "failed_check_owner_page"


# ========== PART 10: RECEIVE WHATSAPP REPLIES ==========
# Requires a public HTTPS address registered with Meta.
# Meta checks the verify token when you first connect the webhook.
# For incoming messages, we check the signature and owner's phone number.


@app.get("/webhook/whatsapp")
def verify_whatsapp(request: Request):
    if MODE != "whatsapp":
        raise HTTPException(404, "WhatsApp mode is off")
    values = request.query_params
    if (values.get("hub.mode") == "subscribe" and
        secrets.compare_digest(values.get("hub.verify_token", ""), WA_VERIFY_TOKEN)):
        return PlainTextResponse(values.get("hub.challenge", ""))
    raise HTTPException(403, "Verification failed")


@app.post("/webhook/whatsapp")
async def incoming_whatsapp(request: Request):
    if MODE != "whatsapp":
        raise HTTPException(404, "WhatsApp mode is off")
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    expected = "sha256=" + hmac.new(WA_APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(403, "Invalid signature")
    try:
        event = json.loads(body)
    except ValueError:
        raise HTTPException(400, "Invalid JSON")

    for entry in event.get("entry", []):
        for change in entry.get("changes", []):
            for msg in change.get("value", {}).get("messages", []):
                message_id = msg.get("id", "")
                sender = re.sub(r"\D", "", msg.get("from", ""))
                # Ignore strangers and non-text messages. They cannot answer visitors.
                if sender != WA_OWNER_PHONE or msg.get("type") != "text" or not message_id:
                    continue
                body_text = msg.get("text", {}).get("body", "")
                with _db_lock, closing(open_db()) as db:
                    try:
                        db.execute("INSERT INTO received_whatsapp (message_id) VALUES (?)", (message_id,))
                        db.commit()
                    except sqlite3.IntegrityError:
                        continue  # Meta sometimes delivers the same event again.
                match = re.fullmatch(r"\s*#(\d+)\s+(.+?)\s*", body_text, re.DOTALL)
                if match:
                    save_owner_answer(int(match.group(1)), match.group(2))
    return {"received": True}


@app.get("/health")
def health_check():
    return {"running": True, "notification_mode": MODE}
