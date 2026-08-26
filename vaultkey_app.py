"""
VaultKey — Professional Secure Password Manager

Security upgrades over the original version:
- AES-256-GCM authenticated encryption (replaces AES-CBC + manual padding)
- Argon2id password hashing / key derivation
- Encryption keys are kept server-side, never in the Flask client cookie
- Opaque server-side session IDs with idle/absolute timeouts
- CSRF protection for state-changing API requests
- Rate limiting on authentication/recovery/generator endpoints
- Secure cookie configuration
- Strong security headers + CSP nonce
- Hashed, single-use, expiring recovery tokens
- Strict input validation and bounded password-generator parameters
- No debug mode in production
- Environment-based configuration

For production, use HTTPS, a Redis-backed session store, a production WSGI server,
and a proper SMTP provider. The included in-memory session store is intentionally
simple for a single-process student/development deployment.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import string
import time
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from threading import Lock
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, redirect, render_template_string, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ===================== CONFIG =====================

class Config:
    DB_PATH = os.getenv("VAULTKEY_DB", "vaultkey.db")
    HOST = os.getenv("VAULTKEY_HOST", "127.0.0.1")
    PORT = int(os.getenv("VAULTKEY_PORT", "5000"))
    DEBUG = os.getenv("VAULTKEY_DEBUG", "0") == "1"
    SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", str(30 * 60)))
    SESSION_ABSOLUTE_SECONDS = int(os.getenv("SESSION_ABSOLUTE_SECONDS", str(8 * 60 * 60)))
    RECOVERY_MINUTES = int(os.getenv("RECOVERY_MINUTES", "30"))
    MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(64 * 1024)))
    APP_ORIGIN = os.getenv("APP_ORIGIN", "http://127.0.0.1:5000")
    SMTP_ENABLED = os.getenv("SMTP_ENABLED", "0") == "1"
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "VaultKey")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USERNAME)


config = Config()
app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=config.MAX_BODY_BYTES,
)

SECRET_KEY = os.getenv("VAULTKEY_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    if not config.DEBUG:
        print("WARNING: VAULTKEY_SECRET_KEY is not set; sessions will be invalidated on restart.")
app.config["SECRET_KEY"] = SECRET_KEY

# Argon2id: deliberately expensive but appropriate for a master-password manager.
PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)


# ===================== SERVER-SIDE SESSIONS =====================

SESSION_STORE = {}
SESSION_LOCK = Lock()


def new_session(user_id, username, enc_key):
    sid = secrets.token_urlsafe(32)
    now = time.time()
    with SESSION_LOCK:
        SESSION_STORE[sid] = {
            "user_id": user_id,
            "username": username,
            "enc_key": enc_key,
            "created": now,
            "last_seen": now,
            "csrf": secrets.token_urlsafe(32),
        }
    return sid


def get_session():
    sid = request.cookies.get("vk_session")
    if not sid:
        return None, None
    with SESSION_LOCK:
        s = SESSION_STORE.get(sid)
        if not s:
            return sid, None
        now = time.time()
        if now - s["last_seen"] > config.SESSION_TTL_SECONDS or now - s["created"] > config.SESSION_ABSOLUTE_SECONDS:
            SESSION_STORE.pop(sid, None)
            return sid, None
        s["last_seen"] = now
        return sid, s


def destroy_session():
    sid = request.cookies.get("vk_session")
    if sid:
        with SESSION_LOCK:
            SESSION_STORE.pop(sid, None)


def session_cookie(response, sid, clear=False):
    response.set_cookie(
        "vk_session",
        sid if not clear else "",
        max_age=None if clear else config.SESSION_TTL_SECONDS,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "0") == "1",
        samesite="Lax",
        path="/",
    )
    return response


def current_user():
    _, s = get_session()
    return s


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        s = current_user()
        if not s:
            return jsonify(success=False, error="Not authenticated"), 401
        return f(*args, **kwargs)
    return wrapped


def csrf_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        s = current_user()
        if not s:
            return jsonify(success=False, error="Not authenticated"), 401
        supplied = request.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(supplied, s["csrf"]):
            return jsonify(success=False, error="CSRF validation failed"), 403
        return f(*args, **kwargs)
    return wrapped


# ===================== DATABASE =====================

def get_db():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                key_salt BLOB NOT NULL,
                recovery_token_hash TEXT,
                recovery_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site_name TEXT NOT NULL,
                site_url TEXT DEFAULT '',
                site_username TEXT NOT NULL,
                encrypted_pw TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'general',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_vault_user_updated
            ON vault(user_id, updated_at DESC);
            """
        )

        # Lightweight migration from the original schema.
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "password_hash" not in columns and "master_hash" in columns:
            # Existing records cannot be safely converted to Argon2id without the user's
            # plaintext master password. Keep the old DB intact and require migration by
            # creating a fresh database rather than silently weakening security.
            raise RuntimeError(
                "Legacy VaultKey database detected. Back it up and start the professional "
                "version with a fresh vaultkey.db; old AES-CBC records are not auto-migrated."
            )


# ===================== CRYPTOGRAPHY =====================

def derive_vault_key(master_password, salt):
    """Derive a 256-bit encryption key with Argon2id."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_password(plaintext, key):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_password(blob, key):
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    if len(raw) < 13:
        raise ValueError("Invalid encrypted password")
    nonce, ciphertext = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")


def hash_recovery_token(token):
    return hmac.new(
        config.SECRET_KEY.encode("utf-8"), token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


# ===================== VALIDATION =====================

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
CATEGORIES = {"general", "social", "work", "finance", "shopping", "entertainment", "dev"}
SYMBOLS = "!@#$%^&*_+-=?"


def validate_master_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        return "Master password must be between 12 and 256 characters"
    return None


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


def validate_vault_item(data):
    if not isinstance(data, dict):
        return "Invalid JSON body"
    site = str(data.get("site_name", "")).strip()
    username = str(data.get("site_username", "")).strip()
    password = data.get("password")
    url = str(data.get("site_url", "")).strip()
    category = str(data.get("category", "general")).strip().lower()

    if not 1 <= len(site) <= 100:
        return "Site name must be 1-100 characters"
    if not 1 <= len(username) <= 320:
        return "Username must be 1-320 characters"
    if not isinstance(password, str) or not 1 <= len(password) <= 2048:
        return "Password must be 1-2048 characters"
    if len(url) > 2048:
        return "URL is too long"
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "Website URL must be a valid HTTP(S) URL"
    if category not in CATEGORIES:
        return "Invalid category"
    return None


def gen_password(length=20, upper=True, lower=True, digits=True, symbols=True):
    try:
        length = int(length)
    except (TypeError, ValueError):
        length = 20
    length = max(12, min(length, 128))

    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        pools = [string.ascii_letters + string.digits]

    chars = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ===================== SECURITY HEADERS =====================

@app.after_request
def security_headers(response):
    nonce = getattr(request, "csp_nonce", "")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.tailwindcss.com; "
        f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    if request.is_secure or os.getenv("COOKIE_SECURE", "0") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.before_request
def request_security():
    request.csp_nonce = secrets.token_urlsafe(18)
    if request.content_length and request.content_length > config.MAX_BODY_BYTES:
        return jsonify(success=False, error="Request too large"), 413


# ===================== EMAIL =====================

def send_recovery_email(email, token, username):
    reset_url = f"{config.APP_ORIGIN.rstrip('/')}/reset-password?token={token}"
    if not config.SMTP_ENABLED:
        print("\n" + "=" * 70)
        print("RECOVERY LINK (development mode):")
        print(reset_url)
        print("=" * 70 + "\n")
        return True

    if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
        app.logger.error("SMTP is enabled but credentials are missing")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "VaultKey - Master Password Recovery"
        msg["From"] = f"{config.SMTP_FROM_NAME} <{config.SMTP_FROM_EMAIL}>"
        msg["To"] = email
        html = f"""
        <html><body style='font-family:sans-serif'>
        <h2>VaultKey password recovery</h2>
        <p>Hello {username},</p>
        <p>A request was made to reset your VaultKey master password.</p>
        <p><a href='{reset_url}'>Reset Master Password</a></p>
        <p>This link expires in {config.RECOVERY_MINUTES} minutes and can be used once.</p>
        <p><strong>Warning:</strong> resetting the master password permanently deletes
        the encrypted vault because VaultKey cannot recover the original master key.</p>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception:
        app.logger.exception("Recovery email delivery failed")
        return False


# ===================== AUTH API =====================

@app.post("/api/register")
@limiter.limit("5 per minute")
def api_register():
    d = json_body()
    if not d:
        return jsonify(success=False, error="Invalid JSON body"), 400

    username = str(d.get("username", "")).strip()
    email = str(d.get("email", "")).strip().lower()
    password = d.get("password", "")

    if not USERNAME_RE.fullmatch(username):
        return jsonify(success=False, error="Username must be 3-32 characters and use letters, numbers, _, ., or -"), 400
    if not EMAIL_RE.fullmatch(email) or len(email) > 320:
        return jsonify(success=False, error="Invalid email"), 400
    error = validate_master_password(password)
    if error:
        return jsonify(success=False, error=error), 400

    now = datetime.now(timezone.utc).isoformat()
    salt = secrets.token_bytes(16)
    password_hash = PASSWORD_HASHER.hash(password)

    try:
        with get_db() as db:
            db.execute(
                """INSERT INTO users
                (username,email,password_hash,key_salt,created_at,updated_at)
                VALUES (?,?,?,?,?,?)""",
                (username, email, password_hash, salt, now, now),
            )
        return jsonify(success=True, message="Account created. Please sign in.")
    except sqlite3.IntegrityError:
        return jsonify(success=False, error="Username or email already exists"), 409


@app.post("/api/login")
@limiter.limit("8 per minute")
def api_login():
    d = json_body()
    if not d:
        return jsonify(success=False, error="Invalid JSON body"), 400
    email = str(d.get("email", "")).strip().lower()
    password = d.get("password", "")

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    valid = False
    if user:
        try:
            PASSWORD_HASHER.verify(user["password_hash"], password)
            valid = True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False

    if not valid:
        return jsonify(success=False, error="Invalid email or master password"), 401

    # Refresh Argon2 parameters if the policy changes later.
    try:
        if PASSWORD_HASHER.check_needs_rehash(user["password_hash"]):
            with get_db() as db:
                db.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                           (PASSWORD_HASHER.hash(password), datetime.now(timezone.utc).isoformat(), user["id"]))
    except Exception:
        app.logger.exception("Password hash upgrade failed")

    key = derive_vault_key(password, user["key_salt"])
    sid = new_session(user["id"], user["username"], key)
    response = jsonify(success=True, message="Logged in", data={"username": user["username"]})
    return session_cookie(response, sid)


@app.post("/api/logout")
@csrf_required
def api_logout():
    destroy_session()
    response = jsonify(success=True, message="Logged out")
    return session_cookie(response, "", clear=True)


@app.get("/api/session")
def api_session():
    s = current_user()
    if not s:
        return jsonify(success=False)
    return jsonify(success=True, data={"username": s["username"], "csrf": s["csrf"]})


@app.post("/api/forgot")
@limiter.limit("3 per 15 minutes")
def api_forgot():
    d = json_body()
    email = str((d or {}).get("email", "")).strip().lower()
    if not email:
        return jsonify(success=False, error="Email required"), 400

    # Always return the same response to prevent account enumeration.
    generic = jsonify(success=True, message="If that email exists, a recovery link was sent.")

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            return generic
        token = secrets.token_urlsafe(48)
        token_hash = hash_recovery_token(token)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=config.RECOVERY_MINUTES)
        db.execute(
            "UPDATE users SET recovery_token_hash=?, recovery_expires_at=?, updated_at=? WHERE id=?",
            (token_hash, expiry.isoformat(), datetime.now(timezone.utc).isoformat(), user["id"]),
        )

    send_recovery_email(user["email"], token, user["username"])
    return generic


@app.get("/api/verify-token")
@limiter.limit("20 per minute")
def api_verify_token():
    token = request.args.get("token", "")
    if not token or len(token) > 256:
        return jsonify(success=False, error="Invalid token"), 400
    token_hash = hash_recovery_token(token)
    with get_db() as db:
        user = db.execute(
            "SELECT id, recovery_expires_at FROM users WHERE recovery_token_hash=?",
            (token_hash,),
        ).fetchone()
    if not user or not user["recovery_expires_at"]:
        return jsonify(success=False, error="Invalid or expired token"), 400
    if datetime.now(timezone.utc) > datetime.fromisoformat(user["recovery_expires_at"]):
        return jsonify(success=False, error="Invalid or expired token"), 400
    return jsonify(success=True)


@app.post("/api/reset-password")
@limiter.limit("5 per 30 minutes")
def api_reset():
    d = json_body()
    if not d:
        return jsonify(success=False, error="Invalid JSON body"), 400
    token = str(d.get("token", ""))
    password = d.get("password", "")
    confirm = d.get("confirm", "")
    if password != confirm:
        return jsonify(success=False, error="Passwords do not match"), 400
    error = validate_master_password(password)
    if error:
        return jsonify(success=False, error=error), 400
    if not token or len(token) > 256:
        return jsonify(success=False, error="Invalid token"), 400

    token_hash = hash_recovery_token(token)
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE recovery_token_hash=?", (token_hash,)
        ).fetchone()
        if not user or not user["recovery_expires_at"]:
            return jsonify(success=False, error="Invalid or expired token"), 400
        if datetime.now(timezone.utc) > datetime.fromisoformat(user["recovery_expires_at"]):
            return jsonify(success=False, error="Invalid or expired token"), 400

        new_salt = secrets.token_bytes(16)
        new_hash = PASSWORD_HASHER.hash(password)
        db.execute(
            """UPDATE users SET password_hash=?, key_salt=?,
            recovery_token_hash=NULL, recovery_expires_at=NULL, updated_at=? WHERE id=?""",
            (new_hash, new_salt, datetime.now(timezone.utc).isoformat(), user["id"]),
        )
        db.execute("DELETE FROM vault WHERE user_id=?", (user["id"],))

    # Invalidate all active sessions for the user.
    with SESSION_LOCK:
        for sid in list(SESSION_STORE):
            if SESSION_STORE[sid]["user_id"] == user["id"]:
                SESSION_STORE.pop(sid, None)

    return jsonify(success=True, message="Master password reset. All stored passwords were deleted.")


# ===================== VAULT API =====================

@app.get("/api/passwords")
@login_required
def api_list_passwords():
    s = current_user()
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM vault WHERE user_id=? ORDER BY updated_at DESC", (s["user_id"],)
        ).fetchall()

    result = []
    for row in rows:
        try:
            password = decrypt_password(row["encrypted_pw"], s["enc_key"])
        except Exception:
            app.logger.exception("Vault decryption failed for record %s", row["id"])
            password = "[DECRYPTION ERROR]"
        result.append({
            "id": row["id"],
            "site_name": row["site_name"],
            "site_url": row["site_url"],
            "site_username": row["site_username"],
            "password": password,
            "category": row["category"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return jsonify(success=True, data=result)


@app.post("/api/passwords")
@login_required
@csrf_required
def api_add_password():
    s = current_user()
    d = json_body()
    error = validate_vault_item(d)
    if error:
        return jsonify(success=False, error=error), 400

    now = datetime.now(timezone.utc).isoformat()
    encrypted = encrypt_password(d["password"], s["enc_key"])
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO vault
            (user_id,site_name,site_url,site_username,encrypted_pw,category,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (
                s["user_id"], str(d["site_name"]).strip(), str(d.get("site_url", "")).strip(),
                str(d["site_username"]).strip(), encrypted,
                str(d.get("category", "general")).strip().lower(), now, now,
            ),
        )
    return jsonify(success=True, message="Password saved", data={"id": cur.lastrowid})


@app.put("/api/passwords/<int:pid>")
@login_required
@csrf_required
def api_update_password(pid):
    s = current_user()
    d = json_body()
    error = validate_vault_item(d)
    if error:
        return jsonify(success=False, error=error), 400

    encrypted = encrypt_password(d["password"], s["enc_key"])
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT id FROM vault WHERE id=? AND user_id=?", (pid, s["user_id"])).fetchone()
        if not row:
            return jsonify(success=False, error="Not found"), 404
        db.execute(
            """UPDATE vault SET site_name=?,site_url=?,site_username=?,encrypted_pw=?,
            category=?,updated_at=? WHERE id=? AND user_id=?""",
            (
                str(d["site_name"]).strip(), str(d.get("site_url", "")).strip(),
                str(d["site_username"]).strip(), encrypted,
                str(d.get("category", "general")).strip().lower(), now, pid, s["user_id"],
            ),
        )
    return jsonify(success=True, message="Password updated")


@app.delete("/api/passwords/<int:pid>")
@login_required
@csrf_required
def api_delete_password(pid):
    s = current_user()
    with get_db() as db:
        cur = db.execute("DELETE FROM vault WHERE id=? AND user_id=?", (pid, s["user_id"]))
        if cur.rowcount != 1:
            return jsonify(success=False, error="Not found"), 404
    return jsonify(success=True, message="Password deleted")


@app.post("/api/generate")
@limiter.limit("60 per minute")
@login_required
def api_generate():
    d = json_body() or {}
    password = gen_password(
        d.get("length", 20),
        bool(d.get("upper", True)),
        bool(d.get("lower", True)),
        bool(d.get("digits", True)),
        bool(d.get("symbols", True)),
    )
    return jsonify(success=True, data={"password": password})


# ===================== PAGES =====================

@app.get("/reset-password")
def page_reset():
    return render_template_string(HTML, page="reset", csp_nonce=request.csp_nonce)


@app.get("/")
def index():
    return render_template_string(HTML, page="dashboard" if current_user() else "auth", csp_nonce=request.csp_nonce)


@app.get("/dashboard")
@login_required
def page_dashboard():
    return render_template_string(HTML, page="dashboard", csp_nonce=request.csp_nonce)


# ===================== ORIGINAL UI, WITH SECURITY INTEGRATION =====================
# The existing UI is intentionally retained so the security work does not force a
# frontend rewrite. The important client-side change is that every state-changing
# request now sends X-CSRF-Token and the encryption key is no longer in the cookie.
HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VaultKey</title>
<script nonce="{{ csp_nonce }}" src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style nonce="{{ csp_nonce }}">
:root{--bg:#080c14;--bg2:#0f172a;--card:#151f32;--card-h:#1a2740;--border:#1e3048;--accent:#10b981;--accent2:#059669;--glow:rgba(16,185,129,.15);--text:#e2e8f0;--muted:#64748b;--danger:#ef4444;--warn:#f59e0b}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Space Grotesk',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}.mono{font-family:'JetBrains Mono',monospace}
.bg-mesh{position:fixed;inset:0;z-index:0;overflow:hidden;pointer-events:none}.bg-mesh .orb{position:absolute;border-radius:50%;filter:blur(100px);opacity:.3;animation:drift 20s ease-in-out infinite}.bg-mesh .orb:nth-child(1){width:500px;height:500px;background:#059669;top:-10%;left:-10%}.bg-mesh .orb:nth-child(2){width:400px;height:400px;background:#0d9488;bottom:-15%;right:-10%;animation-delay:-7s;animation-duration:25s}.bg-mesh .orb:nth-child(3){width:300px;height:300px;background:#065f46;top:50%;left:60%;animation-delay:-14s;animation-duration:30s}@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(60px,-40px) scale(1.1)}50%{transform:translate(-30px,60px) scale(.95)}75%{transform:translate(40px,30px) scale(1.05)}}
.page{position:relative;z-index:1;min-height:100vh}.page.hidden{display:none}.glass{background:rgba(15,23,42,.75);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px}.vk-input{width:100%;padding:12px 16px;background:rgba(8,12,20,.7);border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:inherit;font-size:15px;outline:none}.vk-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}.vk-input::placeholder{color:var(--muted)}.vk-input-wrap{position:relative}.vk-input-wrap .tp{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:4px}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 24px;border-radius:10px;font-family:inherit;font-size:15px;font-weight:600;cursor:pointer;border:none;text-decoration:none}.btn-primary{background:linear-gradient(135deg,var(--accent2),var(--accent));color:#fff}.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}.btn-danger{background:rgba(239,68,68,.12);color:var(--danger);border:1px solid rgba(239,68,68,.25)}.btn-sm{padding:8px 14px;font-size:13px;border-radius:8px}.btn-icon{width:36px;height:36px;padding:0;border-radius:8px;font-size:14px}.sbar{height:4px;border-radius:2px;background:var(--border);overflow:hidden;margin-top:8px}.sbar .fill{height:100%;border-radius:2px}.tab-btn{padding:10px 20px;background:none;border:none;color:var(--muted);font-family:inherit;font-size:15px;font-weight:500;cursor:pointer;position:relative}.tab-btn.active{color:var(--accent)}.tab-btn.active::after{content:'';position:absolute;bottom:-1px;left:20%;right:20%;height:2px;background:var(--accent)}.pw-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px}.pw-card .si{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px;flex-shrink:0}#toasts{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;pointer-events:none}.toast{pointer-events:auto;padding:14px 20px;border-radius:10px;font-size:14px;font-weight:500;display:flex;align-items:center;gap:10px;min-width:280px;border:1px solid}.toast-success{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.3);color:#6ee7b7}.toast-error{background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.3);color:#fca5a5}.toast-info{background:rgba(6,182,212,.15);border-color:rgba(6,182,212,.3);color:#67e8f9}.mo{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px}.mo.hidden{display:none}.mo-box{width:100%;max-width:500px;max-height:90vh;overflow-y:auto}.cat-badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}.sw{position:relative;flex:1;max-width:400px}.sw i{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px}.sw input{padding-left:40px}.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}@keyframes spin{to{transform:rotate(360deg)}}.vk-sel{appearance:none;padding:10px 36px 10px 14px;background:rgba(8,12,20,.7);border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:inherit;font-size:14px;outline:none;cursor:pointer;width:100%}.link{color:var(--accent);cursor:pointer;text-decoration:none;font-size:14px}@media(max-width:640px){.pw-grid{grid-template-columns:1fr!important}.dh{flex-direction:column;gap:12px}.sw{max-width:100%}}
</style></head><body>
<div class="bg-mesh"><div class="orb"></div><div class="orb"></div><div class="orb"></div></div><div id="toasts"></div>

<div id="page-auth" class="page {{ 'hidden' if page != 'auth' else '' }}"><div class="flex items-center justify-center min-h-screen px-4 py-8"><div class="glass w-full max-w-md p-8">
<div class="text-center mb-8"><div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-600 to-emerald-400 mb-4"><i class="fas fa-key text-2xl text-white"></i></div><h1 class="text-2xl font-bold">VaultKey</h1><p class="text-sm mt-1" style="color:var(--muted)">Professional secure password manager</p></div>
<div class="flex border-b mb-6" style="border-color:var(--border)"><button class="tab-btn active" data-tab="login">Sign In</button><button class="tab-btn" data-tab="register">Register</button></div>
<form id="form-login" class="space-y-4"><div><label class="block text-sm mb-1.5">Email</label><input type="email" class="vk-input" id="login-email" required></div><div><label class="block text-sm mb-1.5">Master Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="login-password" required><button type="button" class="tp" data-target="login-password"><i class="fas fa-eye"></i></button></div></div><button type="submit" class="btn btn-primary w-full" id="btn-login">Sign In</button><p class="text-center"><span class="link" id="show-forgot">Forgot password?</span></p></form>
<form id="form-register" class="space-y-4 hidden"><div><label class="block text-sm mb-1.5">Username</label><input type="text" class="vk-input" id="reg-username" required></div><div><label class="block text-sm mb-1.5">Email</label><input type="email" class="vk-input" id="reg-email" required></div><div><label class="block text-sm mb-1.5">Master Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="reg-password" required><button type="button" class="tp" data-target="reg-password"><i class="fas fa-eye"></i></button></div><p class="text-xs mt-1" id="rs-txt" style="color:var(--muted)">Use at least 12 characters.</p></div><div><label class="block text-sm mb-1.5">Confirm Password</label><input type="password" class="vk-input" id="reg-confirm" required></div><button type="submit" class="btn btn-primary w-full" id="btn-register">Create Account</button></form>
<form id="form-forgot" class="space-y-4 hidden"><button type="button" class="link mb-2" id="back-to-login">← Back to sign in</button><h3 class="text-lg font-semibold">Recover Master Password</h3><p class="text-sm" style="color:var(--muted)">Enter your account email.</p><input type="email" class="vk-input" id="forgot-email" required><button type="submit" class="btn btn-primary w-full" id="btn-forgot">Send Recovery Link</button></form>
</div></div></div>

<div id="page-dashboard" class="page {{ 'hidden' if page != 'dashboard' else '' }}"><header class="sticky top-0 z-50" style="background:rgba(8,12,20,.9);backdrop-filter:blur(16px);border-bottom:1px solid var(--border)"><div class="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4 dh"><a href="/dashboard" class="flex items-center gap-2 flex-shrink-0" style="text-decoration:none;color:var(--text)"><div class="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-600 to-emerald-400 flex items-center justify-center"><i class="fas fa-key text-sm text-white"></i></div><span class="font-bold text-lg hidden sm:inline">VaultKey</span></a><div class="sw"><i class="fas fa-search"></i><input type="text" class="vk-input" id="search-input" placeholder="Search passwords..."></div><div class="flex items-center gap-2 flex-shrink-0"><button class="btn btn-ghost btn-sm" id="btn-ogen"><i class="fas fa-bolt"></i><span class="hidden sm:inline">Generate</span></button><button class="btn btn-primary btn-sm" id="btn-oadd"><i class="fas fa-plus"></i><span class="hidden sm:inline">Add Password</span></button><button class="btn btn-icon btn-ghost" id="btn-umenu"><i class="fas fa-user-circle"></i></button><div id="udrop" class="hidden absolute right-4 top-16 glass p-2 w-48"><p class="px-3 py-2 text-sm font-medium truncate" id="duname"></p><button class="btn btn-ghost btn-sm w-full justify-start" id="btn-logout"><i class="fas fa-sign-out-alt"></i> Sign Out</button></div></div></div></header><main class="max-w-6xl mx-auto px-4 py-8"><div class="grid grid-cols-2 sm:grid-cols-3 gap-4 mb-8"><div class="glass p-4"><p class="text-sm" style="color:var(--muted)">Total Passwords</p><p class="text-2xl font-bold mt-1" id="st-total">0</p></div><div class="glass p-4"><p class="text-sm" style="color:var(--muted)">Strong</p><p class="text-2xl font-bold mt-1" style="color:var(--accent)" id="st-strong">0</p></div><div class="glass p-4"><p class="text-sm" style="color:var(--muted)">Weak</p><p class="text-2xl font-bold mt-1" style="color:var(--danger)" id="st-weak">0</p></div></div><div class="pw-grid grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4" id="pw-list"></div><div class="hidden text-center py-16" id="empty-state"><i class="fas fa-lock text-5xl mb-4" style="color:var(--border)"></i><h3 class="text-xl font-semibold mb-2">Your vault is empty</h3><button class="btn btn-primary" id="btn-eadd"><i class="fas fa-plus"></i> Add Password</button></div></main></div>

<div id="page-reset" class="page {{ 'hidden' if page != 'reset' else '' }}"><div class="flex items-center justify-center min-h-screen px-4 py-8"><div class="glass w-full max-w-md p-8"><h1 class="text-xl font-bold mb-4">Reset Master Password</h1><div id="rload" class="text-center py-8"><div class="spinner"></div><p class="text-sm mt-3">Verifying recovery token...</p></div><div id="rform" class="hidden"><div class="p-4 rounded-xl mb-6" style="background:rgba(239,68,68,.08)"><p class="text-sm" style="color:#fca5a5"><b>Warning:</b> Resetting permanently deletes the encrypted vault.</p></div><form id="form-reset" class="space-y-4"><input type="password" class="vk-input" id="rpassword" placeholder="New master password" required><input type="password" class="vk-input" id="rconfirm" placeholder="Confirm password" required><input type="text" class="vk-input" id="rconftxt" placeholder="Type DELETE ALL" required><button type="submit" class="btn btn-danger w-full" id="btn-reset">Reset Master Password</button></form></div><div id="rerr" class="hidden text-center py-8"><p class="font-semibold" id="rerr-msg">Invalid or expired token</p><a href="/" class="link mt-4 inline-block">Go to sign in</a></div><div id="rok" class="hidden text-center py-8"><p class="font-semibold">Master password has been reset</p><p class="text-sm mt-2">All stored passwords were deleted.</p><a href="/" class="btn btn-primary mt-6 inline-flex">Sign In</a></div></div></div></div>

<div id="m-pw" class="mo hidden"><div class="mo-box glass p-6"><div class="flex items-center justify-between mb-6"><h2 class="text-lg font-bold" id="m-pw-title">Add Password</h2><button class="btn btn-icon btn-ghost" onclick="cm('m-pw')">×</button></div><form id="form-pw" class="space-y-4"><input type="hidden" id="pw-id"><div class="grid grid-cols-2 gap-4"><input type="text" class="vk-input" id="pw-site" placeholder="Site name" required><select class="vk-sel" id="pw-cat"><option value="general">General</option><option value="social">Social</option><option value="work">Work</option><option value="finance">Finance</option><option value="shopping">Shopping</option><option value="entertainment">Entertainment</option><option value="dev">Development</option></select></div><input type="url" class="vk-input" id="pw-url" placeholder="https://example.com"><input type="text" class="vk-input" id="pw-uname" placeholder="Username / Email" required><div class="vk-input-wrap"><input type="password" class="vk-input mono" id="pw-pass" placeholder="Password" required><button type="button" class="tp" data-target="pw-pass"><i class="fas fa-eye"></i></button></div><div class="flex gap-3"><button type="button" class="btn btn-ghost flex-1" onclick="cm('m-pw')">Cancel</button><button type="submit" class="btn btn-primary flex-1" id="btn-save">Save</button></div></form></div></div>
<div id="m-gen" class="mo hidden"><div class="mo-box glass p-6"><h2 class="text-lg font-bold mb-4">Password Generator</h2><p class="mono text-lg break-all select-all mb-4" id="gen-out">Click generate</p><input type="range" min="12" max="128" value="20" class="w-full" id="gen-len"><div class="flex gap-3 mt-4"><button class="btn btn-ghost flex-1" id="btn-gcopy">Copy</button><button class="btn btn-primary flex-1" id="btn-ggo">Generate</button><button class="btn btn-primary flex-1 hidden" id="btn-guse">Use This</button></div></div></div>
<div id="m-del" class="mo hidden"><div class="mo-box glass p-6 text-center"><h2 class="text-lg font-bold mb-2">Delete Password</h2><p class="text-sm mb-6">Delete <b id="del-name"></b>?</p><input type="hidden" id="del-id"><div class="flex gap-3"><button class="btn btn-ghost flex-1" onclick="cm('m-del')">Cancel</button><button class="btn btn-danger flex-1" id="btn-cdel">Delete</button></div></div></div>

<script nonce="{{ csp_nonce }}">
var P=[],EID=null,GCB=null,CSRF=null;
var CC={general:{bg:'rgba(100,116,139,.15)',text:'#94a3b8'},social:{bg:'rgba(236,72,153,.15)',text:'#f472b6'},work:{bg:'rgba(6,182,212,.15)',text:'#22d3ee'},finance:{bg:'rgba(245,158,11,.15)',text:'#fbbf24'},shopping:{bg:'rgba(249,115,22,.15)',text:'#fb923c'},entertainment:{bg:'rgba(168,85,247,.15)',text:'#c084fc'},dev:{bg:'rgba(16,185,129,.15)',text:'#34d399'}};
var IC=['#10b981','#f59e0b','#ef4444','#06b6d4','#ec4899','#f97316','#14b8a6','#84cc16'];
function $(id){return document.getElementById(id)} function ic(n){var h=0;for(var i=0;i<n.length;i++)h=n.charCodeAt(i)+((h<<5)-h);return IC[Math.abs(h)%IC.length]}
function cs(pw){var s=0;if(!pw)return{s:0,p:0};if(pw.length>=8)s++;if(pw.length>=12)s++;if(pw.length>=16)s++;if(/[A-Z]/.test(pw))s++;if(/[a-z]/.test(pw))s++;if(/\d/.test(pw))s++;if(/[^A-Za-z0-9]/.test(pw))s++;s=Math.min(s,6);return{s:s,p:Math.round(s/6*100)}}
function toast(m,tp){var e=document.createElement('div');e.className='toast toast-'+(tp||'info');e.textContent=m;$('toasts').appendChild(e);setTimeout(function(){e.remove()},3500)}
function om(id){$(id).classList.remove('hidden')} function cm(id){$(id).classList.add('hidden')}
function api(u,o){o=o||{};o.headers=o.headers||{};o.headers['Content-Type']='application/json';if(CSRF)o.headers['X-CSRF-Token']=CSRF;return fetch(u,o).then(function(r){return r.json().then(function(d){if(!r.ok||!d.success)throw new Error(d.error||'Request failed');return d})})}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}

document.querySelectorAll('.tp').forEach(function(b){b.addEventListener('click',function(){var i=$(b.dataset.target),x=b.querySelector('i');if(i.type==='password'){i.type='text';x.className='fas fa-eye-slash'}else{i.type='password';x.className='fas fa-eye'}})});
document.querySelectorAll('.tab-btn').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('.tab-btn').forEach(function(x){x.classList.remove('active')});b.classList.add('active');var t=b.dataset.tab;$('form-login').classList.toggle('hidden',t!=='login');$('form-register').classList.toggle('hidden',t!=='register');$('form-forgot').classList.add('hidden')})});
$('show-forgot').addEventListener('click',function(){$('form-login').classList.add('hidden');$('form-forgot').classList.remove('hidden')});$('back-to-login').addEventListener('click',function(){$('form-forgot').classList.add('hidden');$('form-login').classList.remove('hidden')});
$('form-register').addEventListener('submit',function(e){e.preventDefault();var pw=$('reg-password').value;if(pw!==$('reg-confirm').value)return toast('Passwords do not match','error');if(pw.length<12)return toast('Master password must be at least 12 characters','error');api('/api/register',{method:'POST',body:JSON.stringify({username:$('reg-username').value,email:$('reg-email').value,password:pw})}).then(function(){toast('Account created','success');$('form-register').reset();document.querySelector('[data-tab="login"]').click()}).catch(function(e){toast(e.message,'error')})});
$('form-login').addEventListener('submit',function(e){e.preventDefault();api('/api/login',{method:'POST',body:JSON.stringify({email:$('login-email').value,password:$('login-password').value})}).then(function(d){toast('Welcome back, '+d.data.username,'success');setTimeout(function(){location.href='/dashboard'},300)}).catch(function(e){toast(e.message,'error')})});
$('form-forgot').addEventListener('submit',function(e){e.preventDefault();api('/api/forgot',{method:'POST',body:JSON.stringify({email:$('forgot-email').value})}).then(function(){toast('If that email exists, a recovery link was sent','success')}).catch(function(e){toast(e.message,'error')})});
$('btn-logout').addEventListener('click',function(){api('/api/logout',{method:'POST'}).finally(function(){location.href='/'})});$('btn-umenu').addEventListener('click',function(e){e.stopPropagation();$('udrop').classList.toggle('hidden')});document.addEventListener('click',function(){$('udrop').classList.add('hidden')});
function loadSession(){return fetch('/api/session').then(function(r){return r.json()}).then(function(d){if(d.success){CSRF=d.data.csrf;$('duname').textContent=d.data.username}else{CSRF=null}})}
function loadPw(){api('/api/passwords').then(function(d){P=d.data||[];renderPw();upStats()}).catch(function(e){if(e.message==='Not authenticated')location.href='/';else toast('Failed to load vault','error')})}
function renderPw(f){f=(f||'').toLowerCase();var l=$('pw-list'),em=$('empty-state');var fl=P.filter(function(p){return p.site_name.toLowerCase().includes(f)||p.site_username.toLowerCase().includes(f)||p.category.toLowerCase().includes(f)});if(P.length===0){l.innerHTML='';em.classList.remove('hidden');return}em.classList.add('hidden');if(fl.length===0){l.innerHTML='<div class="col-span-full text-center py-12">No results found</div>';return}l.innerHTML=fl.map(function(p){var co=ic(p.site_name),ca=CC[p.category]||CC.general,s=cs(p.password);return '<div class="pw-card" data-id="'+p.id+'"><div class="flex items-start gap-3 mb-3"><div class="si" style="background:'+co+'22;color:'+co+'">'+esc(p.site_name.charAt(0).toUpperCase())+'</div><div class="flex-1 min-w-0"><div class="flex items-center gap-2"><h3 class="font-semibold truncate">'+esc(p.site_name)+'</h3><span class="cat-badge" style="background:'+ca.bg+';color:'+ca.text+'">'+esc(p.category)+'</span></div><p class="text-sm truncate" style="color:var(--muted)">'+esc(p.site_username)+'</p></div></div><div class="flex items-center gap-2 mb-3 p-2.5 rounded-lg" style="background:rgba(8,12,20,.5)"><span class="mono text-sm flex-1 truncate pm" data-pw="'+esc(p.password)+'" data-rv="false">••••••••••••</span><div class="sbar flex-shrink-0" style="width:40px;height:3px"><div class="fill" style="width:'+s.p+'%;background:var(--accent)"></div></div></div><div class="flex items-center gap-1.5"><button class="btn btn-icon btn-ghost btn-sm trv"><i class="fas fa-eye"></i></button><button class="btn btn-icon btn-ghost btn-sm cpw"><i class="fas fa-copy"></i></button><button class="btn btn-icon btn-ghost btn-sm cus"><i class="fas fa-user"></i></button><div class="flex-1"></div><button class="btn btn-icon btn-ghost btn-sm edt"><i class="fas fa-pen"></i></button><button class="btn btn-icon btn-ghost btn-sm del" style="color:var(--danger)"><i class="fas fa-trash"></i></button></div></div>'}).join('');
l.querySelectorAll('.trv').forEach(function(b){b.onclick=function(){var sp=b.closest('.pw-card').querySelector('.pm');var rv=sp.dataset.rv==='true';sp.textContent=rv?'••••••••••••':sp.dataset.pw;sp.dataset.rv=(!rv).toString();b.querySelector('i').className=rv?'fas fa-eye':'fas fa-eye-slash'}});l.querySelectorAll('.cpw').forEach(function(b){b.onclick=function(){navigator.clipboard.writeText(b.closest('.pw-card').querySelector('.pm').dataset.pw);toast('Password copied','success')}});l.querySelectorAll('.cus').forEach(function(b){b.onclick=function(){var p=P.find(function(x){return x.id===+b.closest('.pw-card').dataset.id});if(p)navigator.clipboard.writeText(p.site_username)}});l.querySelectorAll('.edt').forEach(function(b){b.onclick=function(){openEdit(+b.closest('.pw-card').dataset.id)}});l.querySelectorAll('.del').forEach(function(b){b.onclick=function(){var id=+b.closest('.pw-card').dataset.id,p=P.find(function(x){return x.id===id});$('del-id').value=id;$('del-name').textContent=p?p.site_name:'';om('m-del')}})}
function upStats(){$('st-total').textContent=P.length;var a=0,b=0;P.forEach(function(p){var s=cs(p.password);if(s.s>=4)a++;if(s.s<=2)b++});$('st-strong').textContent=a;$('st-weak').textContent=b} $('search-input').addEventListener('input',function(e){renderPw(e.target.value)});
function openAdd(){EID=null;$('m-pw-title').textContent='Add Password';$('form-pw').reset();om('m-pw')}function openEdit(id){var p=P.find(function(x){return x.id===id});if(!p)return;EID=id;$('m-pw-title').textContent='Edit Password';$('pw-site').value=p.site_name;$('pw-url').value=p.site_url;$('pw-uname').value=p.site_username;$('pw-pass').value=p.password;$('pw-cat').value=p.category;om('m-pw')}$('btn-oadd').onclick=openAdd;$('btn-eadd').onclick=openAdd;
$('form-pw').addEventListener('submit',function(e){e.preventDefault();var pl={site_name:$('pw-site').value,site_url:$('pw-url').value,site_username:$('pw-uname').value,password:$('pw-pass').value,category:$('pw-cat').value};api(EID?'/api/passwords/'+EID:'/api/passwords',{method:EID?'PUT':'POST',body:JSON.stringify(pl)}).then(function(){toast(EID?'Password updated':'Password saved','success');cm('m-pw');loadPw()}).catch(function(e){toast(e.message,'error')})});
$('btn-cdel').onclick=function(){api('/api/passwords/'+$('del-id').value,{method:'DELETE'}).then(function(){cm('m-del');loadPw();toast('Password deleted','success')}).catch(function(e){toast(e.message,'error')});};
function doGen(){api('/api/generate',{method:'POST',body:JSON.stringify({length:+$('gen-len').value})}).then(function(d){$('gen-out').textContent=d.data.password}).catch(function(e){toast(e.message,'error')})}$('btn-ogen').onclick=function(){GCB=null;$('btn-guse').classList.add('hidden');doGen();om('m-gen')};$('btn-ggo').onclick=doGen;$('btn-mgen')&&($('btn-mgen').onclick=doGen);$('btn-gcopy').onclick=function(){navigator.clipboard.writeText($('gen-out').textContent);toast('Copied','success')};
(function(){if(!$('page-reset').classList.contains('hidden')){var tk=new URLSearchParams(location.search).get('token');if(!tk){$('rload').classList.add('hidden');$('rerr').classList.remove('hidden');return}api('/api/verify-token?token='+encodeURIComponent(tk)).then(function(){$('rload').classList.add('hidden');$('rform').classList.remove('hidden')}).catch(function(e){$('rload').classList.add('hidden');$('rerr').classList.remove('hidden');$('rerr-msg').textContent=e.message})}})();
$('form-reset').addEventListener('submit',function(e){e.preventDefault();var pw=$('rpassword').value,cf=$('rconfirm').value;if(pw!==cf)return toast('Passwords do not match','error');if($('rconftxt').value!=='DELETE ALL')return toast('Type DELETE ALL to confirm','error');var tk=new URLSearchParams(location.search).get('token');api('/api/reset-password',{method:'POST',body:JSON.stringify({token:tk,password:pw,confirm:cf})}).then(function(){$('rform').classList.add('hidden');$('rok').classList.remove('hidden')}).catch(function(e){toast(e.message,'error')})});
(function(){if(!$('page-dashboard').classList.contains('hidden')){loadSession().then(loadPw)}})();document.querySelectorAll('.mo').forEach(function(m){m.addEventListener('click',function(e){if(e.target===m)m.classList.add('hidden')})});document.addEventListener('keydown',function(e){if(e.key==='Escape')document.querySelectorAll('.mo:not(.hidden)').forEach(function(m){m.classList.add('hidden')})});
</script></body></html>'''


# ===================== STARTUP =====================

if __name__ == "__main__":
    init_db()
    print("\nVaultKey — Professional Secure Password Manager")
    print("=" * 52)
    print(f"Running at {config.APP_ORIGIN}")
    print(f"Database: {os.path.abspath(config.DB_PATH)}")
    print(f"SMTP: {'ENABLED' if config.SMTP_ENABLED else 'DEV MODE'}")
    print("Security: Argon2id + AES-256-GCM + CSRF + rate limiting")
    print("NOTE: Use a production WSGI server and HTTPS outside development.")
    print()
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
