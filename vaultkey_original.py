"""
VaultKey — Secure Password Manager
====================================
AES-256-CBC · PBKDF2-SHA256 (600K iterations) · Email recovery
Install:  pip install flask cryptography
Run:      python app.py
"""

import os, hashlib, secrets, string, sqlite3, smtplib, re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from base64 import b64encode, b64decode

from flask import (Flask, request, session, redirect, url_for,
                   jsonify, render_template_string)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

SMTP_CONFIG = {
    'enabled': False,
    'host': 'smtp.gmail.com',
    'port': 587,
    'username': 'your_email@gmail.com',
    'password': 'your_app_password',
    'from_name': 'VaultKey',
    'from_email': 'your_email@gmail.com',
}

DB_PATH = 'vaultkey.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            master_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            recovery_token TEXT,
            token_expiry TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_name TEXT NOT NULL,
            site_url TEXT DEFAULT '',
            site_username TEXT NOT NULL,
            encrypted_pw TEXT NOT NULL,
            iv TEXT NOT NULL,
            category TEXT DEFAULT 'general',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

def derive_key(master_pw, salt):
    return hashlib.pbkdf2_hmac('sha256', master_pw.encode(), bytes.fromhex(salt), 600000, dklen=32)

def hash_master(master_pw, salt):
    return derive_key(master_pw, salt).hex()

def verify_master(master_pw, stored_hash, salt):
    return secrets.compare_digest(hash_master(master_pw, salt), stored_hash)

def encrypt_pw(plaintext, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return b64encode(iv).decode(), b64encode(ct).decode()

def decrypt_pw(iv_b64, ct_b64, key):
    iv, ct = b64decode(iv_b64), b64decode(ct_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def send_recovery_email(email, token, username):
    url = "http://" + request.host + "/reset-password?token=" + token
    if not SMTP_CONFIG['enabled']:
        print("\n" + "=" * 58)
        print("  RECOVERY LINK (dev mode):")
        print("  " + url)
        print("=" * 58 + "\n")
        return True
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'VaultKey - Master Password Recovery'
        msg['From'] = SMTP_CONFIG['from_name'] + " <" + SMTP_CONFIG['from_email'] + ">"
        msg['To'] = email
        html = ('<div style="font-family:sans-serif;max-width:560px;margin:0 auto;'
                'background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden">'
                '<div style="background:linear-gradient(135deg,#059669,#10b981);padding:28px;'
                'text-align:center"><h1 style="margin:0;font-size:22px;color:#fff">'
                'VaultKey Recovery</h1></div>'
                '<div style="padding:28px">'
                '<p>Hello <b>' + username + '</b>, click below to reset:</p>'
                '<div style="text-align:center;margin:28px 0">'
                '<a href="' + url + '" style="background:linear-gradient(135deg,#059669,#10b981);'
                'color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;'
                'font-weight:600">Reset Password</a></div>'
                '<p style="color:#fca5a5;font-size:14px"><b>Warning:</b> This will '
                '<b>permanently delete all stored passwords</b>.</p>'
                '<p style="color:#64748b;font-size:13px;margin-top:16px">'
                'Link expires in 30 minutes.</p></div></div>')
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP(SMTP_CONFIG['host'], SMTP_CONFIG['port']) as s:
            s.starttls()
            s.login(SMTP_CONFIG['username'], SMTP_CONFIG['password'])
            s.send_message(msg)
        return True
    except Exception as e:
        print("Email error:", e)
        return False

def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session:
            return jsonify(success=False, error='Not authenticated'), 401
        return f(*a, **kw)
    return wrap

def get_key():
    k = session.get('enc_key')
    return bytes.fromhex(k) if k else None

def gen_password(length=20, upper=True, lower=True, digits=True, symbols=True):
    chars = ''
    if lower:   chars += string.ascii_lowercase
    if upper:   chars += string.ascii_uppercase
    if digits:  chars += string.digits
    if symbols: chars += '!@#$%^&*_+-=?'
    if not chars: chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

@app.after_request
def sec_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Cache-Control'] = 'no-store'
    return resp

# ===================== AUTH API =====================
@app.route('/api/register', methods=['POST'])
def api_register():
    d = request.json
    if not d or not d.get('username') or not d.get('email') or not d.get('password'):
        return jsonify(success=False, error='All fields required'), 400
    if len(d['password']) < 8:
        return jsonify(success=False, error='Master password must be at least 8 characters'), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', d['email']):
        return jsonify(success=False, error='Invalid email'), 400
    salt = secrets.token_hex(16)
    mh = hash_master(d['password'], salt)
    try:
        db = get_db()
        db.execute('INSERT INTO users (username,email,master_hash,salt,created_at) VALUES (?,?,?,?,?)',
                   (d['username'].strip(), d['email'].strip().lower(), mh, salt, datetime.utcnow().isoformat()))
        db.commit()
        db.close()
        return jsonify(success=True, message='Account created. Please sign in.')
    except sqlite3.IntegrityError:
        return jsonify(success=False, error='Username or email already exists'), 409

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.json
    if not d or not d.get('email') or not d.get('password'):
        return jsonify(success=False, error='Email and password required'), 400
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (d['email'].strip().lower(),)).fetchone()
    db.close()
    if not user or not verify_master(d['password'], user['master_hash'], user['salt']):
        return jsonify(success=False, error='Invalid email or master password'), 401
    key = derive_key(d['password'], user['salt'])
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['enc_key'] = key.hex()
    return jsonify(success=True, message='Logged in', data={'username': user['username']})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify(success=True, message='Logged out')

@app.route('/api/forgot', methods=['POST'])
def api_forgot():
    d = request.json
    if not d or not d.get('email'):
        return jsonify(success=False, error='Email required'), 400
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (d['email'].strip().lower(),)).fetchone()
    if not user:
        db.close()
        return jsonify(success=True, message='If that email exists, a recovery link was sent.')
    token = secrets.token_urlsafe(48)
    expiry = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
    db.execute('UPDATE users SET recovery_token=?, token_expiry=? WHERE id=?', (token, expiry, user['id']))
    db.commit()
    db.close()
    send_recovery_email(user['email'], token, user['username'])
    return jsonify(success=True, message='If that email exists, a recovery link was sent.')

@app.route('/api/verify-token', methods=['GET'])
def api_verify_token():
    token = request.args.get('token', '')
    if not token:
        return jsonify(success=False, error='No token'), 400
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE recovery_token=?', (token,)).fetchone()
    db.close()
    if not user or not user['token_expiry']:
        return jsonify(success=False, error='Invalid token'), 400
    if datetime.utcnow() > datetime.fromisoformat(user['token_expiry']):
        return jsonify(success=False, error='Token expired'), 400
    pw_count = get_db().execute('SELECT COUNT(*) as c FROM vault WHERE user_id=?', (user['id'],)).fetchone()['c']
    return jsonify(success=True, data={'username': user['username'], 'password_count': pw_count})

@app.route('/api/reset-password', methods=['POST'])
def api_reset():
    d = request.json
    if not d or not d.get('token') or not d.get('password') or not d.get('confirm'):
        return jsonify(success=False, error='All fields required'), 400
    if d['password'] != d['confirm']:
        return jsonify(success=False, error='Passwords do not match'), 400
    if len(d['password']) < 8:
        return jsonify(success=False, error='Password must be at least 8 characters'), 400
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE recovery_token=?', (d['token'],)).fetchone()
    if not user or not user['token_expiry']:
        db.close()
        return jsonify(success=False, error='Invalid token'), 400
    if datetime.utcnow() > datetime.fromisoformat(user['token_expiry']):
        db.close()
        return jsonify(success=False, error='Token expired'), 400
    salt = secrets.token_hex(16)
    mh = hash_master(d['password'], salt)
    db.execute('UPDATE users SET master_hash=?, salt=?, recovery_token=NULL, token_expiry=NULL WHERE id=?', (mh, salt, user['id']))
    db.execute('DELETE FROM vault WHERE user_id=?', (user['id'],))
    db.commit()
    db.close()
    return jsonify(success=True, message='Master password reset. All stored passwords deleted.')

# ===================== PASSWORDS CRUD =====================
@app.route('/api/passwords', methods=['GET'])
@login_required
def api_list_passwords():
    key = get_key()
    if not key:
        return jsonify(success=False, error='Session error'), 401
    db = get_db()
    rows = db.execute('SELECT * FROM vault WHERE user_id=? ORDER BY updated_at DESC', (session['user_id'],)).fetchall()
    db.close()
    result = []
    for r in rows:
        try:
            pw = decrypt_pw(r['iv'], r['encrypted_pw'], key)
        except Exception:
            pw = '[DECRYPTION ERROR]'
        result.append({'id': r['id'], 'site_name': r['site_name'], 'site_url': r['site_url'],
                       'site_username': r['site_username'], 'password': pw, 'category': r['category'],
                       'created_at': r['created_at'], 'updated_at': r['updated_at']})
    return jsonify(success=True, data=result)

@app.route('/api/passwords', methods=['POST'])
@login_required
def api_add_password():
    key = get_key()
    if not key:
        return jsonify(success=False, error='Session error'), 401
    d = request.json
    if not d or not d.get('site_name') or not d.get('site_username') or not d.get('password'):
        return jsonify(success=False, error='Site name, username, and password required'), 400
    iv, ct = encrypt_pw(d['password'], key)
    now = datetime.utcnow().isoformat()
    db = get_db()
    cur = db.execute('INSERT INTO vault (user_id,site_name,site_url,site_username,encrypted_pw,iv,category,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
                     (session['user_id'], d['site_name'].strip(), d.get('site_url', '').strip(),
                      d['site_username'].strip(), ct, iv, d.get('category', 'general'), now, now))
    db.commit()
    pid = cur.lastrowid
    db.close()
    return jsonify(success=True, message='Password saved', data={'id': pid})

@app.route('/api/passwords/<int:pid>', methods=['PUT'])
@login_required
def api_update_password(pid):
    key = get_key()
    if not key:
        return jsonify(success=False, error='Session error'), 401
    d = request.json
    if not d or not d.get('site_name') or not d.get('site_username') or not d.get('password'):
        return jsonify(success=False, error='All fields required'), 400
    iv, ct = encrypt_pw(d['password'], key)
    now = datetime.utcnow().isoformat()
    db = get_db()
    row = db.execute('SELECT id FROM vault WHERE id=? AND user_id=?', (pid, session['user_id'])).fetchone()
    if not row:
        db.close()
        return jsonify(success=False, error='Not found'), 404
    db.execute('UPDATE vault SET site_name=?,site_url=?,site_username=?,encrypted_pw=?,iv=?,category=?,updated_at=? WHERE id=?',
               (d['site_name'].strip(), d.get('site_url', '').strip(), d['site_username'].strip(),
                ct, iv, d.get('category', 'general'), now, pid))
    db.commit()
    db.close()
    return jsonify(success=True, message='Password updated')

@app.route('/api/passwords/<int:pid>', methods=['DELETE'])
@login_required
def api_delete_password(pid):
    db = get_db()
    row = db.execute('SELECT id FROM vault WHERE id=? AND user_id=?', (pid, session['user_id'])).fetchone()
    if not row:
        db.close()
        return jsonify(success=False, error='Not found'), 404
    db.execute('DELETE FROM vault WHERE id=?', (pid,))
    db.commit()
    db.close()
    return jsonify(success=True, message='Password deleted')

@app.route('/api/generate', methods=['POST'])
def api_generate():
    d = request.json or {}
    return jsonify(success=True, data={'password': gen_password(
        length=d.get('length', 20), upper=d.get('upper', True), lower=d.get('lower', True),
        digits=d.get('digits', True), symbols=d.get('symbols', True))})

@app.route('/api/session', methods=['GET'])
def api_session():
    if 'user_id' in session:
        return jsonify(success=True, data={'username': session.get('username', '')})
    return jsonify(success=False)

# ===================== PAGE ROUTES =====================
@app.route('/reset-password')
def page_reset():
    return render_template_string(HTML, page='reset')

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template_string(HTML, page='dashboard')
    return render_template_string(HTML, page='auth')

@app.route('/dashboard')
def page_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template_string(HTML, page='dashboard')

# ===================== HTML TEMPLATE =====================
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VaultKey</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{--bg:#080c14;--bg2:#0f172a;--card:#151f32;--card-h:#1a2740;--border:#1e3048;--accent:#10b981;--accent2:#059669;--glow:rgba(16,185,129,.15);--text:#e2e8f0;--muted:#64748b;--danger:#ef4444;--warn:#f59e0b}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Space Grotesk',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
.mono{font-family:'JetBrains Mono',monospace}
.bg-mesh{position:fixed;inset:0;z-index:0;overflow:hidden;pointer-events:none}
.bg-mesh .orb{position:absolute;border-radius:50%;filter:blur(100px);opacity:.3;animation:drift 20s ease-in-out infinite}
.bg-mesh .orb:nth-child(1){width:500px;height:500px;background:#059669;top:-10%;left:-10%}
.bg-mesh .orb:nth-child(2){width:400px;height:400px;background:#0d9488;bottom:-15%;right:-10%;animation-delay:-7s;animation-duration:25s}
.bg-mesh .orb:nth-child(3){width:300px;height:300px;background:#065f46;top:50%;left:60%;animation-delay:-14s;animation-duration:30s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(60px,-40px) scale(1.1)}50%{transform:translate(-30px,60px) scale(.95)}75%{transform:translate(40px,30px) scale(1.05)}}
.page{position:relative;z-index:1;min-height:100vh}.page.hidden{display:none}
.glass{background:rgba(15,23,42,.75);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px}
.vk-input{width:100%;padding:12px 16px;background:rgba(8,12,20,.7);border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:inherit;font-size:15px;outline:none;transition:border-color .2s,box-shadow .2s}
.vk-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
.vk-input::placeholder{color:var(--muted)}
.vk-input-wrap{position:relative}
.vk-input-wrap .tp{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:4px;transition:color .2s}
.vk-input-wrap .tp:hover{color:var(--text)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 24px;border-radius:10px;font-family:inherit;font-size:15px;font-weight:600;cursor:pointer;border:none;transition:all .2s;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--accent2),var(--accent));color:#fff;box-shadow:0 4px 20px rgba(16,185,129,.25)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 28px rgba(16,185,129,.35)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--muted);background:rgba(255,255,255,.03)}
.btn-danger{background:rgba(239,68,68,.12);color:var(--danger);border:1px solid rgba(239,68,68,.25)}
.btn-danger:hover{background:rgba(239,68,68,.2)}
.btn-sm{padding:8px 14px;font-size:13px;border-radius:8px}
.btn-icon{width:36px;height:36px;padding:0;border-radius:8px;font-size:14px}
.sbar{height:4px;border-radius:2px;background:var(--border);overflow:hidden;margin-top:8px}
.sbar .fill{height:100%;border-radius:2px;transition:width .3s,background .3s}
.tab-btn{padding:10px 20px;background:none;border:none;color:var(--muted);font-family:inherit;font-size:15px;font-weight:500;cursor:pointer;position:relative;transition:color .2s}
.tab-btn.active{color:var(--accent)}
.tab-btn.active::after{content:'';position:absolute;bottom:-1px;left:20%;right:20%;height:2px;background:var(--accent);border-radius:1px}
.tab-btn:hover{color:var(--text)}
.pw-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;transition:all .25s}
.pw-card:hover{background:var(--card-h);border-color:rgba(16,185,129,.2);transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,0,0,.3)}
.pw-card .si{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px;color:#fff;flex-shrink:0}
#toasts{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;pointer-events:none}
.toast{pointer-events:auto;padding:14px 20px;border-radius:10px;font-size:14px;font-weight:500;display:flex;align-items:center;gap:10px;animation:slideIn .3s ease;min-width:280px;backdrop-filter:blur(12px);border:1px solid}
.toast-success{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.3);color:#6ee7b7}
.toast-error{background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.3);color:#fca5a5}
.toast-info{background:rgba(6,182,212,.15);border-color:rgba(6,182,212,.3);color:#67e8f9}
@keyframes slideIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}
@keyframes slideOut{from{opacity:1;transform:translateX(0)}to{opacity:0;transform:translateX(40px)}}
.mo{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeIn .2s}
.mo.hidden{display:none}
.mo-box{width:100%;max-width:500px;max-height:90vh;overflow-y:auto}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.cat-badge{display:inline-block;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.sw{position:relative;flex:1;max-width:400px}
.sw i{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px}
.sw input{padding-left:40px}
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.vk-sel{appearance:none;padding:10px 36px 10px 14px;background:rgba(8,12,20,.7) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2364748b'%3E%3Cpath d='M6 8L1 3h10z'/%3E%3C/svg%3E") no-repeat right 12px center;border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:inherit;font-size:14px;outline:none;cursor:pointer;width:100%}
.vk-sel:focus{border-color:var(--accent)}.vk-sel option{background:var(--bg2);color:var(--text)}
.link{color:var(--accent);cursor:pointer;text-decoration:none;font-size:14px;transition:opacity .2s}.link:hover{opacity:.8}
@media(max-width:640px){.pw-grid{grid-template-columns:1fr!important}.dh{flex-direction:column;gap:12px}.sw{max-width:100%}}
</style>
</head>
<body>
<div class="bg-mesh"><div class="orb"></div><div class="orb"></div><div class="orb"></div></div>
<div id="toasts"></div>

<!-- AUTH -->
<div id="page-auth" class="page {{ 'hidden' if page != 'auth' else '' }}">
<div class="flex items-center justify-center min-h-screen px-4 py-8">
<div class="glass w-full max-w-md p-8">
  <div class="text-center mb-8">
    <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-600 to-emerald-400 mb-4"><i class="fas fa-key text-2xl text-white"></i></div>
    <h1 class="text-2xl font-bold tracking-tight">VaultKey</h1>
    <p class="text-sm mt-1" style="color:var(--muted)">Secure password manager</p>
  </div>
  <div class="flex border-b mb-6" style="border-color:var(--border)">
    <button class="tab-btn active" data-tab="login">Sign In</button>
    <button class="tab-btn" data-tab="register">Register</button>
  </div>
  <form id="form-login" class="space-y-4">
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Email</label><input type="email" class="vk-input" id="login-email" placeholder="you@example.com" required></div>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Master Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="login-password" placeholder="Enter master password" required><button type="button" class="tp" data-target="login-password"><i class="fas fa-eye"></i></button></div></div>
    <button type="submit" class="btn btn-primary w-full" id="btn-login">Sign In</button>
    <p class="text-center"><span class="link" id="show-forgot">Forgot password?</span></p>
  </form>
  <form id="form-register" class="space-y-4 hidden">
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Username</label><input type="text" class="vk-input" id="reg-username" placeholder="Choose a username" required></div>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Email</label><input type="email" class="vk-input" id="reg-email" placeholder="you@example.com" required></div>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Master Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="reg-password" placeholder="Min 8 characters" required><button type="button" class="tp" data-target="reg-password"><i class="fas fa-eye"></i></button></div><div class="sbar"><div class="fill" id="rs-fill" style="width:0%"></div></div><p class="text-xs mt-1" id="rs-txt" style="color:var(--muted)"></p></div>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Confirm Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="reg-confirm" placeholder="Repeat master password" required></div></div>
    <button type="submit" class="btn btn-primary w-full" id="btn-register">Create Account</button>
  </form>
  <form id="form-forgot" class="space-y-4 hidden">
    <button type="button" class="link mb-2" id="back-to-login"><i class="fas fa-arrow-left mr-1"></i> Back to sign in</button>
    <h3 class="text-lg font-semibold">Recover Master Password</h3>
    <p class="text-sm" style="color:var(--muted)">Enter the email associated with your account.</p>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Email</label><input type="email" class="vk-input" id="forgot-email" placeholder="you@example.com" required></div>
    <button type="submit" class="btn btn-primary w-full" id="btn-forgot">Send Recovery Link</button>
  </form>
</div>
</div>
</div>

<!-- DASHBOARD -->
<div id="page-dashboard" class="page {{ 'hidden' if page != 'dashboard' else '' }}">
<header class="sticky top-0 z-50" style="background:rgba(8,12,20,.85);backdrop-filter:blur(16px);border-bottom:1px solid var(--border)">
  <div class="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4 dh">
    <a href="/dashboard" class="flex items-center gap-2 flex-shrink-0" style="text-decoration:none;color:var(--text)"><div class="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-600 to-emerald-400 flex items-center justify-center"><i class="fas fa-key text-sm text-white"></i></div><span class="font-bold text-lg hidden sm:inline">VaultKey</span></a>
    <div class="sw"><i class="fas fa-search"></i><input type="text" class="vk-input" id="search-input" placeholder="Search passwords..."></div>
    <div class="flex items-center gap-2 flex-shrink-0">
      <button class="btn btn-ghost btn-sm" id="btn-ogen"><i class="fas fa-bolt"></i><span class="hidden sm:inline">Generate</span></button>
      <button class="btn btn-primary btn-sm" id="btn-oadd"><i class="fas fa-plus"></i><span class="hidden sm:inline">Add Password</span></button>
      <div class="relative"><button class="btn btn-icon btn-ghost" id="btn-umenu"><i class="fas fa-user-circle"></i></button>
        <div id="udrop" class="hidden absolute right-0 top-full mt-2 glass p-2 w-48" style="border-radius:10px">
          <p class="px-3 py-2 text-sm font-medium truncate" id="duname"></p>
          <hr style="border-color:var(--border);margin:4px 0">
          <button class="btn btn-ghost btn-sm w-full justify-start" id="btn-logout"><i class="fas fa-sign-out-alt"></i> Sign Out</button>
        </div>
      </div>
    </div>
  </div>
</header>
<main class="max-w-6xl mx-auto px-4 py-8">
  <div class="grid grid-cols-2 sm:grid-cols-3 gap-4 mb-8">
    <div class="glass p-4"><p class="text-sm" style="color:var(--muted)">Total Passwords</p><p class="text-2xl font-bold mt-1" id="st-total">0</p></div>
    <div class="glass p-4"><p class="text-sm" style="color:var(--muted)">Strong</p><p class="text-2xl font-bold mt-1" style="color:var(--accent)" id="st-strong">0</p></div>
    <div class="glass p-4 col-span-2 sm:col-span-1"><p class="text-sm" style="color:var(--muted)">Weak</p><p class="text-2xl font-bold mt-1" style="color:var(--danger)" id="st-weak">0</p></div>
  </div>
  <div class="pw-grid grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4" id="pw-list"></div>
  <div class="hidden text-center py-16" id="empty-state"><i class="fas fa-lock text-5xl mb-4" style="color:var(--border)"></i><h3 class="text-xl font-semibold mb-2">Your vault is empty</h3><p class="text-sm mb-6" style="color:var(--muted)">Add your first password to get started.</p><button class="btn btn-primary" id="btn-eadd"><i class="fas fa-plus"></i> Add Password</button></div>
</main>
</div>

<!-- RESET -->
<div id="page-reset" class="page {{ 'hidden' if page != 'reset' else '' }}">
<div class="flex items-center justify-center min-h-screen px-4 py-8">
<div class="glass w-full max-w-md p-8">
  <div class="text-center mb-6"><div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-500 to-orange-500 mb-4"><i class="fas fa-unlock-alt text-xl text-white"></i></div><h1 class="text-xl font-bold">Reset Master Password</h1></div>
  <div id="rload" class="text-center py-8"><div class="spinner"></div><p class="text-sm mt-3" style="color:var(--muted)">Verifying recovery token...</p></div>
  <div id="rform" class="hidden">
    <div class="p-4 rounded-xl mb-6" style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2)"><p class="text-sm" style="color:#fca5a5"><i class="fas fa-exclamation-triangle mr-2"></i><b>Warning:</b> This will <b>permanently delete all <span id="rpwcount">0</span> stored passwords</b>. Without the original master password, encrypted data cannot be recovered.</p></div>
    <form id="form-reset" class="space-y-4">
      <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">New Master Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="rpassword" placeholder="Min 8 characters" required><button type="button" class="tp" data-target="rpassword"><i class="fas fa-eye"></i></button></div><div class="sbar"><div class="fill" id="rt-fill" style="width:0%"></div></div><p class="text-xs mt-1" id="rt-txt" style="color:var(--muted)"></p></div>
      <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Confirm New Password</label><div class="vk-input-wrap"><input type="password" class="vk-input" id="rconfirm" placeholder="Repeat new password" required></div></div>
      <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Type <b style="color:var(--danger)">DELETE ALL</b> to confirm</label><input type="text" class="vk-input" id="rconftxt" placeholder="DELETE ALL" required></div>
      <button type="submit" class="btn btn-danger w-full" id="btn-reset">Reset Master Password</button>
    </form>
  </div>
  <div id="rerr" class="hidden text-center py-8"><i class="fas fa-times-circle text-3xl mb-3" style="color:var(--danger)"></i><p class="font-semibold" id="rerr-msg">Invalid or expired token</p><a href="/" class="link mt-4 inline-block">Go to sign in</a></div>
  <div id="rok" class="hidden text-center py-8"><i class="fas fa-check-circle text-3xl mb-3" style="color:var(--accent)"></i><p class="font-semibold">Master password has been reset</p><p class="text-sm mt-2" style="color:var(--muted)">All stored passwords have been deleted. Sign in with your new password.</p><a href="/" class="btn btn-primary mt-6 inline-flex">Sign In</a></div>
</div>
</div>
</div>

<!-- ADD/EDIT MODAL -->
<div id="m-pw" class="mo hidden">
<div class="mo-box glass p-6">
  <div class="flex items-center justify-between mb-6"><h2 class="text-lg font-bold" id="m-pw-title">Add Password</h2><button class="btn btn-icon btn-ghost" onclick="cm('m-pw')"><i class="fas fa-times"></i></button></div>
  <form id="form-pw" class="space-y-4">
    <input type="hidden" id="pw-id">
    <div class="grid grid-cols-2 gap-4">
      <div class="col-span-2 sm:col-span-1"><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Site Name</label><input type="text" class="vk-input" id="pw-site" placeholder="e.g. GitHub" required></div>
      <div class="col-span-2 sm:col-span-1"><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Category</label><select class="vk-sel" id="pw-cat"><option value="general">General</option><option value="social">Social</option><option value="work">Work</option><option value="finance">Finance</option><option value="shopping">Shopping</option><option value="entertainment">Entertainment</option><option value="dev">Development</option></select></div>
    </div>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Website URL</label><input type="url" class="vk-input" id="pw-url" placeholder="https://github.com"></div>
    <div><label class="block text-sm font-medium mb-1.5" style="color:var(--muted)">Username / Email</label><input type="text" class="vk-input" id="pw-uname" placeholder="user@email.com" required></div>
    <div><div class="flex items-center justify-between mb-1.5"><label class="text-sm font-medium" style="color:var(--muted)">Password</label><button type="button" class="link text-xs" id="btn-mgen"><i class="fas fa-bolt mr-1"></i>Generate</button></div><div class="vk-input-wrap"><input type="password" class="vk-input mono" id="pw-pass" placeholder="Enter or generate password" required><button type="button" class="tp" data-target="pw-pass"><i class="fas fa-eye"></i></button></div></div>
    <div class="flex gap-3 pt-2"><button type="button" class="btn btn-ghost flex-1" onclick="cm('m-pw')">Cancel</button><button type="submit" class="btn btn-primary flex-1" id="btn-save">Save</button></div>
  </form>
</div>
</div>

<!-- GENERATOR MODAL -->
<div id="m-gen" class="mo hidden">
<div class="mo-box glass p-6">
  <div class="flex items-center justify-between mb-6"><h2 class="text-lg font-bold">Password Generator</h2><button class="btn btn-icon btn-ghost" onclick="cm('m-gen')"><i class="fas fa-times"></i></button></div>
  <div class="p-4 rounded-xl mb-4" style="background:rgba(8,12,20,.7);border:1px solid var(--border)"><p class="mono text-lg break-all select-all" id="gen-out" style="color:var(--accent);min-height:28px">Click generate</p></div>
  <div class="space-y-4">
    <div><div class="flex justify-between text-sm mb-2"><span style="color:var(--muted)">Length</span><span class="font-semibold" id="gen-lv">20</span></div><input type="range" min="8" max="64" value="20" class="w-full accent-emerald-500" id="gen-len"></div>
    <div class="grid grid-cols-2 gap-3">
      <label class="flex items-center gap-2 cursor-pointer text-sm"><input type="checkbox" checked id="gen-up" class="accent-emerald-500"> Uppercase</label>
      <label class="flex items-center gap-2 cursor-pointer text-sm"><input type="checkbox" checked id="gen-lo" class="accent-emerald-500"> Lowercase</label>
      <label class="flex items-center gap-2 cursor-pointer text-sm"><input type="checkbox" checked id="gen-di" class="accent-emerald-500"> Digits</label>
      <label class="flex items-center gap-2 cursor-pointer text-sm"><input type="checkbox" checked id="gen-sy" class="accent-emerald-500"> Symbols</label>
    </div>
    <div class="flex gap-3"><button class="btn btn-ghost flex-1" id="btn-gcopy"><i class="fas fa-copy"></i> Copy</button><button class="btn btn-primary flex-1" id="btn-ggo"><i class="fas fa-bolt"></i> Generate</button><button class="btn btn-primary flex-1 hidden" id="btn-guse"><i class="fas fa-check"></i> Use This</button></div>
  </div>
</div>
</div>

<!-- DELETE MODAL -->
<div id="m-del" class="mo hidden">
<div class="mo-box glass p-6 text-center">
  <i class="fas fa-trash-alt text-3xl mb-4" style="color:var(--danger)"></i>
  <h2 class="text-lg font-bold mb-2">Delete Password</h2>
  <p class="text-sm mb-6" style="color:var(--muted)">Delete password for <b id="del-name" style="color:var(--text)"></b>? This cannot be undone.</p>
  <input type="hidden" id="del-id">
  <div class="flex gap-3"><button class="btn btn-ghost flex-1" onclick="cm('m-del')">Cancel</button><button class="btn btn-danger flex-1" id="btn-cdel">Delete</button></div>
</div>
</div>

<script>
var P=[],EID=null,GCB=null;
var CC={general:{bg:"rgba(100,116,139,.15)",text:"#94a3b8"},social:{bg:"rgba(236,72,153,.15)",text:"#f472b6"},work:{bg:"rgba(6,182,212,.15)",text:"#22d3ee"},finance:{bg:"rgba(245,158,11,.15)",text:"#fbbf24"},shopping:{bg:"rgba(249,115,22,.15)",text:"#fb923c"},entertainment:{bg:"rgba(168,85,247,.15)",text:"#c084fc"},dev:{bg:"rgba(16,185,129,.15)",text:"#34d399"}};
var IC=["#10b981","#f59e0b","#ef4444","#06b6d4","#ec4899","#f97316","#14b8a6","#84cc16"];
function ic(n){var h=0;for(var i=0;i<n.length;i++)h=n.charCodeAt(i)+((h<<5)-h);return IC[Math.abs(h)%IC.length]}
function cs(pw){if(!pw)return{s:0,l:"",c:"var(--border)",p:0};var s=0;if(pw.length>=8)s++;if(pw.length>=12)s++;if(pw.length>=16)s++;if(/[A-Z]/.test(pw))s++;if(/[a-z]/.test(pw))s++;if(/\d/.test(pw))s++;if(/[^A-Za-z0-9]/.test(pw))s++;s=Math.min(s,6);var L=["","Very Weak","Weak","Fair","Good","Strong","Very Strong"];var C=["","var(--danger)","#f97316","var(--warn)","#84cc16","var(--accent)","#059669"];return{s:s,l:L[s],c:C[s],p:Math.round(s/6*100)}}
function usb(iid,fid,tid){var pw=$(iid).value,s=cs(pw),f=$(fid),t=$(tid);f.style.width=s.p+"%";f.style.background=s.c;t.textContent=pw?s.l:"";t.style.color=s.c}
function $(id){return document.getElementById(id)}
function toast(m,tp){tp=tp||"info";var e=document.createElement("div");e.className="toast toast-"+tp;var ic={success:"fa-check-circle",error:"fa-times-circle",info:"fa-info-circle"};e.innerHTML='<i class="fas '+(ic[tp]||ic.info)+'"></i><span>'+m+"</span>";$("toasts").appendChild(e);setTimeout(function(){e.style.animation="slideOut .3s ease forwards";setTimeout(function(){e.remove()},300)},3500)}
function om(id){$(id).classList.remove("hidden")}
function cm(id){$(id).classList.add("hidden")}
function api(u,o){o=o||{};o.headers=o.headers||{};o.headers["Content-Type"]="application/json";return fetch(u,o).then(function(r){return r.json()}).then(function(d){if(!d.success)throw new Error(d.error||"Request failed");return d})}
function esc(s){var d=document.createElement("div");d.textContent=s;return d.innerHTML}
function ea(s){return s.replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/'/g,"&#39;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}

document.querySelectorAll(".tp").forEach(function(b){b.addEventListener("click",function(){var i=$(b.dataset.target),ic=b.querySelector("i");if(i.type==="password"){i.type="text";ic.className="fas fa-eye-slash"}else{i.type="password";ic.className="fas fa-eye"}})});
document.querySelectorAll(".tab-btn").forEach(function(b){b.addEventListener("click",function(){document.querySelectorAll(".tab-btn").forEach(function(x){x.classList.remove("active")});b.classList.add("active");var t=b.dataset.tab;$("form-login").classList.toggle("hidden",t!=="login");$("form-register").classList.toggle("hidden",t!=="register");$("form-forgot").classList.add("hidden")})});
 $("show-forgot").addEventListener("click",function(){$("form-login").classList.add("hidden");$("form-forgot").classList.remove("hidden");document.querySelectorAll(".tab-btn").forEach(function(b){b.classList.remove("active")})});
 $("back-to-login").addEventListener("click",function(){$("form-forgot").classList.add("hidden");$("form-login").classList.remove("hidden");document.querySelector('[data-tab="login"]').classList.add("active")});
 $("reg-password").addEventListener("input",function(){usb("reg-password","rs-fill","rs-txt")});
 $("rpassword").addEventListener("input",function(){usb("rpassword","rt-fill","rt-txt")});

 $("form-register").addEventListener("submit",function(e){e.preventDefault();var pw=$("reg-password").value,cf=$("reg-confirm").value;if(pw!==cf){toast("Passwords do not match","error");return}if(pw.length<8){toast("Password must be at least 8 characters","error");return}var b=$("btn-register");b.disabled=true;b.innerHTML='<span class="spinner"></span> Creating...';api("/api/register",{method:"POST",body:JSON.stringify({username:$("reg-username").value,email:$("reg-email").value,password:pw})}).then(function(){toast("Account created! Please sign in.","success");document.querySelector('[data-tab="login"]').click();$("form-register").reset();$("rs-fill").style.width="0%";$("rs-txt").textContent=""}).catch(function(err){toast(err.message,"error")}).finally(function(){b.disabled=false;b.textContent="Create Account"})});

 $("form-login").addEventListener("submit",function(e){e.preventDefault();var b=$("btn-login");b.disabled=true;b.innerHTML='<span class="spinner"></span> Signing in...';api("/api/login",{method:"POST",body:JSON.stringify({email:$("login-email").value,password:$("login-password").value})}).then(function(d){toast("Welcome back, "+d.data.username+"!","success");setTimeout(function(){window.location.href="/dashboard"},500)}).catch(function(err){toast(err.message,"error")}).finally(function(){b.disabled=false;b.textContent="Sign In"})});

 $("form-forgot").addEventListener("submit",function(e){e.preventDefault();var b=$("btn-forgot");b.disabled=true;b.innerHTML='<span class="spinner"></span> Sending...';api("/api/forgot",{method:"POST",body:JSON.stringify({email:$("forgot-email").value})}).then(function(){toast("Recovery link sent! Check email or console.","success");setTimeout(function(){$("back-to-login").click()},1500)}).catch(function(err){toast(err.message,"error")}).finally(function(){b.disabled=false;b.textContent="Send Recovery Link"})});

 $("btn-logout").addEventListener("click",function(){fetch("/api/logout",{method:"POST"});window.location.href="/"});
 $("btn-umenu").addEventListener("click",function(e){e.stopPropagation();$("udrop").classList.toggle("hidden")});
document.addEventListener("click",function(){$("udrop").classList.add("hidden")});

function loadPw(){api("/api/passwords").then(function(d){P=d.data||[];renderPw();upStats()}).catch(function(err){if(err.message==="Not authenticated")window.location.href="/";else toast("Failed to load passwords","error")})}

function renderPw(f){f=(f||"").toLowerCase();var l=$("pw-list"),em=$("empty-state");var fl=P.filter(function(p){return p.site_name.toLowerCase().indexOf(f)!==-1||p.site_username.toLowerCase().indexOf(f)!==-1||p.category.toLowerCase().indexOf(f)!==-1});if(P.length===0){l.innerHTML="";em.classList.remove("hidden");return}em.classList.add("hidden");if(fl.length===0){l.innerHTML='<div class="col-span-full text-center py-12" style="color:var(--muted)"><i class="fas fa-search text-2xl mb-3 block"></i>No results found</div>';return}
l.innerHTML=fl.map(function(p){var co=ic(p.site_name),ca=CC[p.category]||CC.general,s=cs(p.password);return '<div class="pw-card" data-id="'+p.id+'"><div class="flex items-start gap-3 mb-3"><div class="si" style="background:'+co+'22;color:'+co+'">'+esc(p.site_name.charAt(0).toUpperCase())+'</div><div class="flex-1 min-w-0"><div class="flex items-center gap-2"><h3 class="font-semibold truncate">'+esc(p.site_name)+'</h3><span class="cat-badge" style="background:'+ca.bg+";color:"+ca.text+'">'+p.category+"</span></div><p class='text-sm truncate' style='color:var(--muted)'>"+esc(p.site_username)+"</p></div></div><div class='flex items-center gap-2 mb-3 p-2.5 rounded-lg' style='background:rgba(8,12,20,.5)'><span class='mono text-sm flex-1 truncate pm' data-pw='"+ea(p.password)+"' data-rv='false'>"+'&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;'+"</span><div class='sbar flex-shrink-0' style='width:40px;height:3px'><div class='fill' style='width:"+s.p+"%;background:"+s.c+"'></div></div></div><div class='flex items-center gap-1.5'><button class='btn btn-icon btn-ghost btn-sm trv' title='Show/Hide'><i class='fas fa-eye'></i></button><button class='btn btn-icon btn-ghost btn-sm cpw' title='Copy password'><i class='fas fa-copy'></i></button><button class='btn btn-icon btn-ghost btn-sm cus' title='Copy username'><i class='fas fa-user'></i></button><div class='flex-1'></div><button class='btn btn-icon btn-ghost btn-sm edt' title='Edit'><i class='fas fa-pen'></i></button><button class='btn btn-icon btn-ghost btn-sm del' title='Delete' style='color:var(--danger)'><i class='fas fa-trash'></i></button></div></div>"}).join("");

l.querySelectorAll(".trv").forEach(function(b){b.addEventListener("click",function(){var sp=b.closest(".pw-card").querySelector(".pm"),rv=sp.dataset.rv==="true";if(rv){sp.innerHTML="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;";sp.dataset.rv="false";b.querySelector("i").className="fas fa-eye"}else{sp.textContent=sp.dataset.pw;sp.dataset.rv="true";b.querySelector("i").className="fas fa-eye-slash"}})});
l.querySelectorAll(".cpw").forEach(function(b){b.addEventListener("click",function(){navigator.clipboard.writeText(b.closest(".pw-card").querySelector(".pm").dataset.pw);toast("Password copied","success")})});
l.querySelectorAll(".cus").forEach(function(b){b.addEventListener("click",function(){var id=parseInt(b.closest(".pw-card").dataset.id),pw=P.find(function(x){return x.id===id});if(pw){navigator.clipboard.writeText(pw.site_username);toast("Username copied","success")}})});
l.querySelectorAll(".edt").forEach(function(b){b.addEventListener("click",function(){openEdit(parseInt(b.closest(".pw-card").dataset.id))})});
l.querySelectorAll(".del").forEach(function(b){b.addEventListener("click",function(){var id=parseInt(b.closest(".pw-card").dataset.id),pw=P.find(function(x){return x.id===id});$("del-id").value=id;$("del-name").textContent=pw?pw.site_name:"";om("m-del")})})}

function upStats(){$("st-total").textContent=P.length;var st=0,wk=0;P.forEach(function(p){var s=cs(p.password);if(s.s>=4)st++;else if(s.s<=2)wk++});$("st-strong").textContent=st;$("st-weak").textContent=wk}
 $("search-input").addEventListener("input",function(e){renderPw(e.target.value)});

function openAdd(){EID=null;$("m-pw-title").textContent="Add Password";$("form-pw").reset();$("pw-id").value="";$("btn-save").textContent="Save";om("m-pw")}
function openEdit(id){var pw=P.find(function(x){return x.id===id});if(!pw)return;EID=id;$("m-pw-title").textContent="Edit Password";$("pw-id").value=id;$("pw-site").value=pw.site_name;$("pw-url").value=pw.site_url;$("pw-uname").value=pw.site_username;$("pw-pass").value=pw.password;$("pw-cat").value=pw.category;$("btn-save").textContent="Update";om("m-pw")}
 $("btn-oadd").addEventListener("click",openAdd);$("btn-eadd").addEventListener("click",openAdd);

 $("form-pw").addEventListener("submit",function(e){e.preventDefault();var b=$("btn-save");b.disabled=true;b.innerHTML='<span class="spinner"></span>';var pl={site_name:$("pw-site").value,site_url:$("pw-url").value,site_username:$("pw-uname").value,password:$("pw-pass").value,category:$("pw-cat").value};var u=EID?"/api/passwords/"+EID:"/api/passwords",m=EID?"PUT":"POST";api(u,{method:m,body:JSON.stringify(pl)}).then(function(){toast(EID?"Password updated":"Password saved","success");cm("m-pw");loadPw()}).catch(function(err){toast(err.message,"error")}).finally(function(){b.disabled=false;b.textContent=EID?"Update":"Save"})});

 $("btn-cdel").addEventListener("click",function(){api("/api/passwords/"+$("del-id").value,{method:"DELETE"}).then(function(){toast("Password deleted","success");cm("m-del");loadPw()}).catch(function(err){toast(err.message,"error")})});

function doGen(){api("/api/generate",{method:"POST",body:JSON.stringify({length:parseInt($("gen-len").value),upper:$("gen-up").checked,lower:$("gen-lo").checked,digits:$("gen-di").checked,symbols:$("gen-sy").checked})}).then(function(d){$("gen-out").textContent=d.data.password}).catch(function(err){toast(err.message,"error")})}

 $("btn-ogen").addEventListener("click",function(){GCB=null;$("btn-guse").classList.add("hidden");doGen();om("m-gen")});
 $("btn-mgen").addEventListener("click",function(){GCB=function(pw){$("pw-pass").value=pw};$("btn-guse").classList.remove("hidden");doGen();om("m-gen")});
 $("btn-ggo").addEventListener("click",doGen);
 $("gen-len").addEventListener("input",function(){$("gen-lv").textContent=$("gen-len").value});
["gen-up","gen-lo","gen-di","gen-sy"].forEach(function(id){$(id).addEventListener("change",doGen)});
 $("btn-gcopy").addEventListener("click",function(){var pw=$("gen-out").textContent;if(pw&&pw!=="Click generate"){navigator.clipboard.writeText(pw);toast("Copied to clipboard","success")}});
 $("btn-guse").addEventListener("click",function(){var pw=$("gen-out").textContent;if(pw&&pw!=="Click generate"&&GCB){GCB(pw);cm("m-gen");toast("Password applied","success")}});

(function(){if(!$("page-reset").classList.contains("hidden")){var tk=new URLSearchParams(window.location.search).get("token");if(!tk){$("rload").classList.add("hidden");$("rerr").classList.remove("hidden");$("rerr-msg").textContent="No recovery token provided.";return}api("/api/verify-token?token="+encodeURIComponent(tk)).then(function(d){$("rpwcount").textContent=d.data.password_count;$("rload").classList.add("hidden");$("rform").classList.remove("hidden")}).catch(function(err){$("rload").classList.add("hidden");$("rerr").classList.remove("hidden");$("rerr-msg").textContent=err.message})}})();

 $("form-reset").addEventListener("submit",function(e){e.preventDefault();var pw=$("rpassword").value,cf=$("rconfirm").value,tx=$("rconftxt").value;if(pw!==cf){toast("Passwords do not match","error");return}if(pw.length<8){toast("Password must be at least 8 characters","error");return}if(tx!=="DELETE ALL"){toast('Please type DELETE ALL to confirm',"error");return}var tk=new URLSearchParams(window.location.search).get("token"),b=$("btn-reset");b.disabled=true;b.innerHTML='<span class="spinner"></span> Resetting...';api("/api/reset-password",{method:"POST",body:JSON.stringify({token:tk,password:pw,confirm:cf})}).then(function(){$("rform").classList.add("hidden");$("rok").classList.remove("hidden")}).catch(function(err){toast(err.message,"error")}).finally(function(){b.disabled=false;b.textContent="Reset Master Password"})});

(function(){if(!$("page-dashboard").classList.contains("hidden")){loadPw();fetch("/api/session").then(function(r){return r.json()}).then(function(d){if(d.success)$("duname").textContent=d.data.username})}})();

document.querySelectorAll(".mo").forEach(function(m){m.addEventListener("click",function(e){if(e.target===m)m.classList.add("hidden")})});
document.addEventListener("keydown",function(e){if(e.key==="Escape")document.querySelectorAll(".mo:not(.hidden)").forEach(function(m){m.classList.add("hidden")})});
</script>
</body>
</html>"""

# ===================== MAIN =====================
if __name__ == '__main__':
    init_db()
    print("\n  VaultKey — Secure Password Manager")
    print("  " + "=" * 38)
    print("  Running at http://localhost:5000")
    print("  Database: " + os.path.abspath(DB_PATH))
    em = 'ENABLED' if SMTP_CONFIG['enabled'] else 'DEV MODE (links printed to console)'
    print("  Email: " + em)
    print()
    app.run(debug=True, port=5000)