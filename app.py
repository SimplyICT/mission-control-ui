import io
import logging
import re
from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import hashlib
import hmac as _hmac
import json
import uuid
import os
import time
import base64
import pyotp
import qrcode as _qrcode
import subprocess
import shlex
import requests
from pathlib import Path
from dotenv import load_dotenv

for env_path in [
    "/home/aiagent/mission-control-site/.env",
    os.path.join(os.path.dirname(__file__), ".env"),
]:
    if os.path.exists(env_path):
        load_dotenv(env_path)

app = FastAPI(title="Mission Control UI")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("mission_control_ui")

BASE_DIR = Path(__file__).resolve().parent

# ── Auth ──────────────────────────────────────────────────────────────────────
_SESSION_SECRET = os.getenv("SESSION_SECRET", "")
_COOKIE_NAME    = "mc_auth"
_COOKIE_MAX_AGE = 86400 * 7  # 7 days
_serializer     = URLSafeTimedSerializer(_SESSION_SECRET or "insecure-no-secret-set")
_USERS_FILE     = BASE_DIR / "users.json"

_PUBLIC_PATHS = {"/health", "/login", "/logout", "/2fa-verify", "/api/services-health", "/agent/install", "/help.html", "/devdocs.html"}

# ── TOTP 2FA helpers ──────────────────────────────────────────────────────────
_2FA_PENDING_COOKIE  = "mc_2fa_pending"
_2FA_PENDING_MAX_AGE = 300  # 5 minutes

def _totp_make_secret() -> str:
    return pyotp.random_base32()

def _totp_check(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False

def _totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Mission Control")

def _totp_qr_b64(uri: str) -> str:
    img = _qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def _get_2fa_pending_user(request) -> str:
    """Return username from pending-2FA cookie, or empty string if invalid/expired."""
    token = request.cookies.get(_2FA_PENDING_COOKIE, "")
    if not token:
        return ""
    try:
        data = _serializer.loads(token, max_age=_2FA_PENDING_MAX_AGE)
        return data.get("pending_2fa", "")
    except Exception:
        return ""

# ── Brute-force protection ────────────────────────────────────────────────────
_BF_MAX_ATTEMPTS = 5
_BF_LOCKOUT_SECS = 15 * 60   # 15 minutes
_bf_log: dict = {}            # ip -> {"count": int, "locked_until": float}

def _get_client_ip(request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "unknown")

def _bf_is_locked(ip: str):
    """Returns (locked: bool, seconds_remaining: int)."""
    entry = _bf_log.get(ip)
    if not entry or entry["count"] < _BF_MAX_ATTEMPTS:
        return False, 0
    remaining = entry["locked_until"] - time.time()
    if remaining > 0:
        return True, int(remaining)
    _bf_log.pop(ip, None)
    return False, 0

def _bf_fail(ip: str):
    entry = _bf_log.setdefault(ip, {"count": 0, "locked_until": 0.0})
    entry["count"] += 1
    if entry["count"] >= _BF_MAX_ATTEMPTS:
        entry["locked_until"] = time.time() + _BF_LOCKOUT_SECS
        logger.warning("Brute-force lockout triggered for IP %s", ip)

def _bf_clear(ip: str):
    _bf_log.pop(ip, None)



# All pages available for the permission picker
ALL_PAGES = [
    {"path": "/index-platform.html",          "label": "Platform Home",          "section": "Core"},
    {"path": "/audit-index.html",              "label": "Audit Centre",           "section": "Device Auditing"},
    {"path": "/device-audit.html",             "label": "Device Audit Form",      "section": "Device Auditing"},
    {"path": "/device-records.html",           "label": "Device Records",         "section": "Device Auditing"},
    {"path": "/device-update.html",            "label": "Device Update",          "section": "Device Auditing"},
    {"path": "/audit-reports.html",            "label": "Audit Reports",          "section": "Device Auditing"},
    {"path": "/audit-report-view.html",        "label": "Audit Report View",      "section": "Device Auditing"},
    {"path": "/audit-cleanup.html",            "label": "Audit Cleanup",          "section": "Device Auditing"},
    {"path": "/active-device-register.html",   "label": "Active Device Register", "section": "Device Auditing"},
    {"path": "/director-view.html",            "label": "Director View",          "section": "Executive"},
    {"path": "/remediation.html",              "label": "Remediation Tracker",    "section": "Compliance"},
    {"path": "/incident-register.html",        "label": "Incident Register",      "section": "Compliance"},
    {"path": "/site-onboarding.html",          "label": "Site Onboarding",        "section": "Administration"},
    {"path": "/admin-users.html",              "label": "User Management",        "section": "Administration"},
    {"path": "/help.html",                    "label": "? Help",                 "section": "Administration"},
    {"path": "/devdocs.html",                 "label": "DevDocs",                "section": "Administration"},
    {"path": "/user-guide.html",               "label": "User Guide",             "section": "Administration"},
    {"path": "/agent-status.html",            "label": "Agent Status Monitor",   "section": "Network Monitoring"},
    {"path": "/project_tracker.html",         "label": "SEO Project Tracker",    "section": "Projects"},
    {"path": "/project-manager.html",         "label": "Project Manager",        "section": "Projects"},
]

# Role default page sets (None = all pages)
ROLE_PAGES = {
    "admin": None,
    "coordinator": {
        "/index-platform.html", "/audit-index.html", "/device-audit.html",
        "/device-records.html", "/device-update.html", "/audit-reports.html",
        "/audit-report-view.html", "/audit-cleanup.html", "/active-device-register.html",
        "/remediation.html", "/incident-register.html", "/site-onboarding.html",
        "/user-guide.html", "/project-manager.html", "/project_tracker.html",
        "/agent-status.html",
    },
    "director": {
        "/index-platform.html", "/director-view.html", "/audit-reports.html",
        "/audit-report-view.html", "/remediation.html", "/incident-register.html",
        "/user-guide.html", "/project_tracker.html",
        "/agent-status.html",
    },
    "viewer": {
        "/index-platform.html", "/director-view.html", "/audit-reports.html",
        "/audit-report-view.html", "/user-guide.html", "/project_tracker.html",
        "/agent-status.html",
    },
}


def _load_users():
    try:
        with open(_USERS_FILE, "r") as f:
            return json.load(f).get("users", [])
    except Exception:
        return []


def _save_users(users):
    with open(_USERS_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)


def _get_authenticated_user(request: Request):
    if not _SESSION_SECRET:
        return None
    token = request.cookies.get(_COOKIE_NAME)
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=_COOKIE_MAX_AGE)
        username = data.get("user")
        if not username:
            return None
        for u in _load_users():
            if u.get("username") == username and u.get("active", True):
                return u
        return None
    except Exception:
        return None


def _user_can_access(user: dict, path: str) -> bool:
    role = user.get("role", "viewer")
    if role == "admin":
        return True
    custom = user.get("custom_pages")
    if custom is not None:
        return path in custom
    allowed = ROLE_PAGES.get(role)
    return allowed is None or path in allowed


def _forbidden_html(user: dict, path: str) -> str:
    name = user.get("full_name") or user.get("username", "")
    return (
        "<!DOCTYPE html><html><head><title>Access Denied</title>"
        "<style>body{margin:0;font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh;}"
        ".box{text-align:center;max-width:400px;padding:32px;}"
        ".code{font-size:64px;font-weight:bold;color:#334155;}"
        "h2{color:#f8fafc;margin:8px 0;}p{color:#64748b;}"
        "a{color:#3b82f6;text-decoration:none;}</style></head>"
        "<body><div class='box'>"
        "<div class='code'>403</div>"
        "<h2>Access Denied</h2>"
        "<p>Hi " + name + ", you don't have permission to view <code>" + path + "</code>.</p>"
        "<p><a href='/index-platform.html'>&#9664; Platform Home</a> &nbsp; "
        "<a href='/logout'>Sign Out</a></p>"
        "</div></body></html>"
    )
# ─────────────────────────────────────────────────────────────────────────────
AUDIT_API_BASE = "http://127.0.0.1:8096"
MONITORING_API_BASE = "http://127.0.0.1:8000"
WAZUH_SOC_API_BASE = "http://208.87.135.185:5000/api"
MONITORING_API_KEY = os.getenv("MISSION_API_KEY", "mission-test-key-123")

SERVERS = {
    "local": {
        "host": "127.0.0.1",
        "services": ["ollama", "openwebui", "mission-control-ui", "mission-control-api", "device-audit-api", "nginx"]
    },
    "test": {"host": "10.121.16.60", "services": ["nginx"]},
    "RMM": {"host": "10.121.16.124", "services": ["nginx"]},
    "OCS": {"host": "10.121.16.88", "services": ["nginx"]},
    "ITFLOW": {"host": "10.121.16.95", "services": ["nginx"]},
    "Wazuh": {"host": "10.121.16.231", "services": ["wazuh-manager"]},
    "Docker1": {"host": "10.121.16.36", "services": ["docker"]},
    "Docker2": {"host": "10.121.16.64", "services": ["docker"]},
    "Ansible": {"host": "10.121.16.129", "services": ["ansible"]},
}


def read_html(filename: str):
    path = BASE_DIR / filename
    if not path.exists():
        return HTMLResponse(
            content=f"<h1>File not found</h1><p>{filename} was not found in {BASE_DIR}</p>",
            status_code=404,
        )
    return HTMLResponse(content=path.read_text(encoding="utf-8"))


def run_cmd(cmd, server):
    host = SERVERS[server]["host"]

    if host == "127.0.0.1":
        final = cmd
    else:
        final = f"ssh -o BatchMode=yes -o ConnectTimeout=5 {shlex.quote(host)} {shlex.quote(cmd)}"

    try:
        r = subprocess.run(final, shell=True, capture_output=True, text=True, timeout=15)
        return (r.stdout + "\n" + r.stderr).strip()
    except Exception as e:
        return str(e)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Allow public paths by exact match
    if path in _PUBLIC_PATHS:
        return await call_next(request)
    # Allow SimplyClik web app paths without mission-control auth
    if path.startswith("/admin") or path.startswith("/portal") or path.startswith("/static"):
        return await call_next(request)
    # Allow monitoring API access without auth (backend handles auth via API key)
    if path.startswith("/monitoring-api/"):
        return await call_next(request)
    user = _get_authenticated_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if path.endswith(".html") or path == "/":
        if not _user_can_access(user, path):
            return HTMLResponse(content=_forbidden_html(user, path), status_code=403)
    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
def login_get():
    page = read_html("login.html")
    if isinstance(page, HTMLResponse):
        html = page.body.decode()
        html = html.replace("__ERROR_CLASS__", "").replace("__ERROR__", "")
        return HTMLResponse(content=html)
    return page


@app.post("/login")
async def login_post(request: Request):
    ip = _get_client_ip(request)
    locked, secs = _bf_is_locked(ip)
    if locked:
        mins = secs // 60 + 1
        page = read_html("login.html")
        if isinstance(page, HTMLResponse):
            html = page.body.decode()
            html = html.replace("__ERROR_CLASS__", "visible")
            html = html.replace("__ERROR__", f"Too many failed attempts. Try again in {mins} minute(s).")
            return HTMLResponse(content=html, status_code=429)
        return page

    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    pw_hash  = hashlib.sha256(password.encode()).hexdigest()

    matched = None
    for u in _load_users():
        if u.get("username") == username and u.get("active", True):
            if _hmac.compare_digest(pw_hash, u.get("password_hash", "")):
                matched = u
                break

    if matched:
        _bf_clear(ip)
        # If 2FA is enabled, redirect to verification step
        if matched.get("totp_enabled"):
            pending_token = _serializer.dumps({"pending_2fa": username})
            resp = RedirectResponse(url="/2fa-verify", status_code=302)
            resp.set_cookie(
                _2FA_PENDING_COOKIE, pending_token,
                max_age=_2FA_PENDING_MAX_AGE,
                httponly=True,
                samesite="lax"
            )
            return resp
        token    = _serializer.dumps({"user": username})
        response = RedirectResponse(url="/index-platform.html", status_code=302)
        response.set_cookie(
            _COOKIE_NAME, token,
            max_age=_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax"
        )
        return response

    _bf_fail(ip)
    locked2, secs2 = _bf_is_locked(ip)
    entry = _bf_log.get(ip, {})
    attempts_left = max(0, _BF_MAX_ATTEMPTS - entry.get("count", 0))

    page = read_html("login.html")
    if isinstance(page, HTMLResponse):
        html = page.body.decode()
        html = html.replace("__ERROR_CLASS__", "visible")
        if locked2:
            html = html.replace("__ERROR__", f"Too many failed attempts. Account locked for 15 minutes.")
        else:
            html = html.replace("__ERROR__", f"Invalid username or password. {attempts_left} attempt(s) remaining.")
        return HTMLResponse(content=html, status_code=401)
    return page


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(_COOKIE_NAME)
    return response


# ── User Management API (admin only) ─────────────────────────────────────────

@app.get("/api/users")
def api_list_users(request: Request):
    user = _get_authenticated_user(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    users = _load_users()
    # Strip password hashes from response
    return [
        {k: v for k, v in u.items() if k != "password_hash"}
        for u in users
    ]


@app.post("/api/users")
async def api_create_user(request: Request):
    admin = _get_authenticated_user(request)
    if not admin or admin.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    users = _load_users()
    if any(u.get("username") == username for u in users):
        raise HTTPException(status_code=409, detail="Username already exists")
    new_user = {
        "user_id":       str(uuid.uuid4()),
        "username":      username,
        "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        "full_name":     body.get("full_name") or "",
        "role":          body.get("role") or "viewer",
        "custom_pages":  body.get("custom_pages"),  # None or list
        "active":        body.get("active", True),
        "created_at":    __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    users.append(new_user)
    _save_users(users)
    return {k: v for k, v in new_user.items() if k != "password_hash"}


@app.put("/api/users/{user_id}")
async def api_update_user(user_id: str, request: Request):
    admin = _get_authenticated_user(request)
    if not admin or admin.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    body = await request.json()
    users = _load_users()
    target = next((u for u in users if u.get("user_id") == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Prevent removing last admin
    if target.get("role") == "admin" and body.get("role") and body.get("role") != "admin":
        admin_count = sum(1 for u in users if u.get("role") == "admin" and u.get("active", True))
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the last admin")
    allowed_fields = {"full_name", "role", "custom_pages", "active"}
    for k in allowed_fields:
        if k in body:
            target[k] = body[k]
    if body.get("password"):
        target["password_hash"] = hashlib.sha256(body["password"].encode()).hexdigest()
    _save_users(users)
    return {k: v for k, v in target.items() if k != "password_hash"}


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: str, request: Request):
    admin = _get_authenticated_user(request)
    if not admin or admin.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    users = _load_users()
    target = next((u for u in users if u.get("user_id") == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.get("role") == "admin":
        admin_count = sum(1 for u in users if u.get("role") == "admin" and u.get("active", True))
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    users = [u for u in users if u.get("user_id") != user_id]
    _save_users(users)
    return {"success": True}


@app.get("/api/page-list")
def api_page_list(request: Request):
    user = _get_authenticated_user(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return {"pages": ALL_PAGES, "role_pages": {k: list(v) if v else None for k, v in ROLE_PAGES.items()}}


@app.get("/admin-users.html", response_class=HTMLResponse)
def admin_users():
    return read_html("admin-users.html")


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/agent/install", response_class=HTMLResponse)
def agent_install_page():
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Install Mission Control Agent</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,system-ui,sans-serif; background:#f5f5f7; color:#1d1d1f; line-height:1.6; }
  .container { max-width:680px; margin:60px auto; padding:0 24px; }
  h1 { font-size:1.8rem; font-weight:700; margin-bottom:4px; }
  .subtitle { color:#6e6e73; font-size:1rem; margin-bottom:28px; }
  .card { background:#fff; border-radius:14px; padding:28px; margin-bottom:20px; box-shadow:0 1px 4px rgba(0,0,0,0.06); }
  .btn { display:inline-block; padding:12px 28px; border-radius:10px; font-size:0.95rem; font-weight:600;
         text-decoration:none; cursor:pointer; border:none; }
  .btn-primary { background:#0071e3; color:#fff; }
  .btn-primary:hover { background:#0077ed; }
  .btn-secondary { background:#e8e8ed; color:#1d1d1f; }
  .btn-secondary:hover { background:#d2d2d7; }
  label { display:block; font-weight:600; margin-bottom:4px; font-size:0.85rem; color:#1d1d1f; }
  input { width:100%; padding:10px 14px; border:1px solid #d2d2d7; border-radius:8px; font-size:0.9rem; margin-bottom:14px; }
  input:focus { outline:none; border-color:#0071e3; box-shadow:0 0 0 3px rgba(0,113,227,0.15); }
  .form-row { display:flex; gap:14px; }
  .form-row .field { flex:1; }
  pre { background:#1d1d1f; color:#f5f5f7; padding:18px; border-radius:10px; overflow-x:auto; font-size:0.8rem; margin:14px 0; white-space:pre-wrap; word-break:break-all; }
  .copy-msg { color:#30b94e; font-size:0.85rem; margin-top:6px; display:none; }
  .steps { counter-reset:step; margin-top:6px; }
  .step { margin-bottom:8px; padding-left:30px; position:relative; font-size:0.9rem; color:#515154; }
  .step::before { counter-increment:step; content:counter(step); position:absolute; left:0; top:0;
          width:22px; height:22px; background:#0071e3; color:#fff; border-radius:50%; text-align:center;
          font-size:0.75rem; font-weight:600; line-height:22px; }
  .inline-code { background:#f5f5f7; padding:1px 6px; border-radius:4px; font-size:0.85rem; font-family:monospace; }
</style>
</head>
<body>
<div class="container">
  <h1>Install Mission Control Agent</h1>
  <p class="subtitle">Windows installer for site probe NUCs</p>

  <div class="card">
    <h2 style="margin-bottom:14px;">1. Enter Site Details</h2>
    <div class="field">
      <label>API Key</label>
      <input id="apiKey" type="password" placeholder="e.g. mission-test-key-123" />
    </div>
    <div class="form-row">
      <div class="field">
        <label>Site ID</label>
        <input id="siteId" placeholder="e.g. site-benowa-elc" />
      </div>
      <div class="field">
        <label>Site Name</label>
        <input id="siteName" placeholder="e.g. Benowa ELC" />
      </div>
    </div>
    <div class="form-row">
      <div class="field">
        <label>Agent ID</label>
        <input id="agentId" placeholder="e.g. probe-benowa-nuc" />
      </div>
      <div class="field">
        <label>Subnet</label>
        <input id="subnet" value="192.168.1.0/24" />
      </div>
    </div>
    <button class="btn btn-secondary" onclick="generateCmd()" style="margin-top:4px;">Generate Command</button>
  </div>

  <div class="card" id="cmdCard" style="display:none;">
    <h2 style="margin-bottom:10px;">2. Run This Command</h2>
    <p style="font-size:0.85rem; color:#6e6e73; margin-bottom:8px;">Open <strong>PowerShell as Administrator</strong> and paste:</p>
    <pre id="cmdOutput"></pre>
    <button class="btn btn-secondary" onclick="copyCmd()" style="font-size:0.85rem; padding:8px 16px;">Copy Command</button>
    <span class="copy-msg" id="copyMsg">Copied!</span>
  </div>

  <div class="card" style="color:#6e6e73; font-size:0.85rem;">
    <p style="margin-bottom:10px;">Alternatively, <a href="/monitoring-api/agent/install.ps1" download>download install.ps1</a> manually and run it from your Downloads folder in admin PowerShell.</p>
    <h2 style="margin-bottom:10px; color:#1d1d1f;">What it does</h2>
    <div class="steps">
      <div class="step">Downloads NSSM (service wrapper) if needed</div>
      <div class="step">Downloads and extracts the probe agent package</div>
      <div class="step">Creates Python virtualenv and installs requests</div>
      <div class="step">Registers as Windows service (auto-start on boot)</div>
      <div class="step">Logs at <span class="inline-code">C:\\Program Files\\Mission Probe\\logs\\</span></div>
    </div>
  </div>
</div>

<script>
function generateCmd() {
  var apiKey = document.getElementById('apiKey').value.trim();
  var siteId = document.getElementById('siteId').value.trim();
  var siteName = document.getElementById('siteName').value.trim();
  var agentId = document.getElementById('agentId').value.trim();
  var subnet = document.getElementById('subnet').value.trim();

  if (!apiKey || !siteId || !siteName || !agentId) {
    alert('Please fill in all fields.');
    return;
  }

  var q = String.fromCharCode(39);
  var dq = String.fromCharCode(34);
  var cmd = "powershell -ExecutionPolicy Bypass -Command " + dq +
    "Invoke-WebRequest -Uri " + q + "https://audit.simplyict.com.au/monitoring-api/agent/install.ps1" + q +
    " -OutFile " + dq + "$env:TEMP\\\\install-mp.ps1" + dq + "; " +
    "& " + dq + "$env:TEMP\\\\install-mp.ps1" + dq +
    " -ApiKey " + q + apiKey + q +
    " -SiteId " + q + siteId + q +
    " -SiteName " + q + siteName + q +
    " -AgentId " + q + agentId + q +
    " -Subnet " + q + subnet + q +
    " -ApiBase " + q + "https://audit.simplyict.com.au/monitoring-api" + q +
    dq;

  document.getElementById('cmdOutput').textContent = cmd;
  document.getElementById('cmdCard').style.display = 'block';
  document.getElementById('copyMsg').style.display = 'none';
}

function copyCmd() {
  var cmd = document.getElementById('cmdOutput').textContent;
  navigator.clipboard.writeText(cmd).then(function() {
    document.getElementById('copyMsg').style.display = 'inline';
  });
}
</script>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@app.get("/api/services-health")
def services_health():
    import urllib.request as ureq
    checks = [
        ("Network Monitor",    "http://127.0.0.1:8000/health"),
        ("Device Audit API",   "http://127.0.0.1:8096/"),
    ]
    results = []
    ok_count = 0
    for name, url in checks:
        try:
            with ureq.urlopen(url, timeout=3) as r:
                alive = r.status < 500
        except Exception:
            alive = False
        if alive:
            ok_count += 1
        results.append({"name": name, "ok": alive})
    results.append({"name": "Mission Control UI", "ok": True})
    ok_count += 1
    return {"ok": ok_count, "total": len(checks) + 1, "services": results}




@app.get("/", response_class=HTMLResponse)
def index():
    return read_html("index-platform.html")


@app.get("/index-platform.html", response_class=HTMLResponse)
def index_platform():
    return read_html("index-platform.html")


@app.get("/index.html", response_class=HTMLResponse)
def index_html():
    return read_html("index.html")


@app.get("/mission_control_live_dashboard_v2.html", response_class=HTMLResponse)
def mission_control_live_dashboard_v2():
    return read_html("mission_control_live_dashboard_v2.html")


@app.get("/audit-index.html", response_class=HTMLResponse)
def audit_index():
    return read_html("audit-index.html")


@app.get("/device-records.html", response_class=HTMLResponse)
def device_records():
    return read_html("device-records.html")


@app.get("/device-audit.html", response_class=HTMLResponse)
def device_audit():
    return read_html("device-audit.html")


@app.get("/device-update.html", response_class=HTMLResponse)
def device_update():
    return read_html("device-update.html")


@app.get("/audit-reports.html", response_class=HTMLResponse)
def audit_reports():
    return read_html("audit-reports.html")


@app.get("/audit-remediation.html", response_class=HTMLResponse)
def audit_remediation():
    return read_html("audit-remediation.html")


@app.get("/active-device-register.html", response_class=HTMLResponse)
def active_device_register():
    return read_html("active-device-register.html")


@app.get("/audit-report-view.html", response_class=HTMLResponse)
def audit_report_view():
    return read_html("audit-report-view.html")


@app.get("/director-view.html", response_class=HTMLResponse)
def director_view():
    return read_html("director-view.html")


@app.get("/audit-cleanup.html", response_class=HTMLResponse)
def audit_cleanup():
    return read_html("audit-cleanup.html")




@app.get("/site-onboarding.html", response_class=HTMLResponse)
def site_onboarding():
    return read_html("site-onboarding.html")

@app.get("/user-guide.html", response_class=HTMLResponse)
def user_guide():
    return read_html("user-guide.html")

@app.get("/help.html", response_class=HTMLResponse)
def help_page():
    return read_html("help.html")

@app.get("/devdocs.html", response_class=HTMLResponse)
def devdocs():
    return read_html("devdocs.html")

@app.get("/agent-status.html", response_class=HTMLResponse)
def agent_status():
    return read_html("agent-status.html")

@app.get("/remediation.html", response_class=HTMLResponse)
def remediation():
    return read_html("remediation.html")


@app.get("/incident-register.html", response_class=HTMLResponse)
def incident_register():
    return read_html("incident-register.html")


@app.get("/wazuh-dashboard.html", response_class=HTMLResponse)
def wazuh_dashboard():
    return read_html("wazuh-dashboard.html")


@app.get("/wazuh-alerts.html", response_class=HTMLResponse)
def wazuh_alerts():
    return read_html("wazuh-alerts.html")


@app.get("/wazuh-autopilot.html", response_class=HTMLResponse)
def wazuh_autopilot():
    return read_html("wazuh-autopilot.html")


@app.get("/wazuh-soc.html", response_class=HTMLResponse)
def wazuh_soc_page():
    return read_html("wazuh-soc.html")



@app.get("/api/fleet")
def fleet():
    results = []

    for name in SERVERS:
        raw = run_cmd("""
HOST=$(hostname)
UPTIME=$(uptime -p)
LOAD=$(cat /proc/loadavg | awk '{print $1}')
DISK=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
MEM=$(free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}')
FAILED=$(systemctl --failed --no-pager --plain | grep -E "failed|loaded" | wc -l)

echo "HOST:$HOST"
echo "UPTIME:$UPTIME"
echo "LOAD:$LOAD"
echo "DISK:$DISK"
echo "MEM:$MEM"
echo "FAILED:$FAILED"
""", name)

        data = {
            "name": name,
            "host": "unknown",
            "uptime": "",
            "load": "0",
            "disk": 0,
            "memory": 0,
            "failed": 0,
            "status": "GREEN",
            "services": SERVERS[name]["services"]
        }

        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                if k == "HOST":
                    data["host"] = v
                if k == "UPTIME":
                    data["uptime"] = v
                if k == "LOAD":
                    data["load"] = v
                if k == "DISK":
                    data["disk"] = int(v or 0)
                if k == "MEM":
                    data["memory"] = int(v or 0)
                if k == "FAILED":
                    data["failed"] = int(v or 0)

        if data["failed"] > 0 or data["disk"] > 85 or data["memory"] > 90:
            data["status"] = "RED"
        elif data["disk"] > 75 or data["memory"] > 80 or float(data["load"]) > 2:
            data["status"] = "AMBER"

        results.append(data)

    return results


@app.get("/api/logs/{server}/{service}")
def logs(server: str, service: str):
    if server not in SERVERS:
        return {"error": "server not allowed"}

    if service not in SERVERS[server]["services"]:
        return {"error": "not allowed"}

    return {"logs": run_cmd(f"journalctl -u {service} -n 80 --no-pager", server)}


@app.post("/api/restart/{server}/{service}")
def restart(server: str, service: str):
    if server not in SERVERS:
        return {"error": "server not allowed"}

    if service not in SERVERS[server]["services"]:
        return {"error": "not allowed"}

    return {"result": run_cmd(f"sudo systemctl restart {service}", server)}


@app.api_route("/audit-api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def audit_api_proxy(path: str, request: Request):
    return await proxy_request(AUDIT_API_BASE, path, request, "Audit API proxy error")


@app.api_route("/monitoring-api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def monitoring_api_proxy(path: str, request: Request):
    return await proxy_request(MONITORING_API_BASE, path, request, "Monitoring API proxy error")


# ── Wazuh SOC proxy with auto-auth ──────────────────────────────
_wazuh_soc_token = {"value": ""}

def _wazuh_soc_login():
    """Get a bearer token from the SOC API."""
    import requests as _req
    try:
        r = _req.post(
            f"{WAZUH_SOC_API_BASE}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10,
        )
        if r.ok:
            data = r.json()
            _wazuh_soc_token["value"] = data.get("token", "")
            return _wazuh_soc_token["value"]
    except Exception:
        pass
    return ""

OTX_DATA_FILE = os.path.join(os.path.dirname(__file__), "otx_data.json")
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()


def _load_otx_data() -> dict:
    default = {
        "enabled": bool(OTX_API_KEY),
        "total_iocs": 0,
        "ips": 0,
        "domains": 0,
        "hashes": 0,
        "size_bytes": 0,
        "last_updated": None,
        "message": "Configure OTX_API_KEY in .env to enable AlienVault OTX threat intelligence." if not OTX_API_KEY else None,
    }
    if not os.path.exists(OTX_DATA_FILE):
        return default
    try:
        with open(OTX_DATA_FILE) as f:
            data = json.load(f)
        data["enabled"] = bool(OTX_API_KEY)
        return data
    except Exception:
        return default


@app.get("/wazuh-api/otx/status")
def wazuh_otx_status():
    return _load_otx_data()


@app.get("/wazuh-api/otx/iocs")
def wazuh_otx_iocs(type: str = "", q: str = ""):
    data = _load_otx_data()
    items = data.get("iocs", [])
    if type:
        items = [i for i in items if i.get("type", "").lower() == type.lower()]
    if q:
        ql = q.lower()
        items = [i for i in items if ql in i.get("value", "").lower()]
    return {"total": len(items), "iocs": items}


@app.post("/wazuh-api/otx/refresh")
def wazuh_otx_refresh():
    try:
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "update_otx.py")],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return {"status": "error", "message": result.stderr.strip() or result.stdout.strip()}
        return json.loads(result.stdout.strip().split("\n")[-1])
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "OTX update timed out after 120s"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/wazuh-api/otx/download")
def wazuh_otx_download():
    rules_path = os.path.join(os.path.dirname(__file__), "otx_rules.xml")
    if not os.path.exists(rules_path):
        raise HTTPException(status_code=404, detail="Rules file not found — run update_otx.py first")
    return Response(
        content=open(rules_path, "rb").read(),
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=otx_rules.xml"},
    )


# ── AI SOC Agent Engine ──────────────────────────────────────────────────
from ai_triage import triage_alert
from ai_resolver import auto_resolve, create_case, list_cases, get_case, update_case, get_stats


@app.get("/wazuh-api/autopilot/stats")
def autopilot_stats():
    return get_stats()


@app.get("/wazuh-api/autopilot/trends")
def autopilot_trends():
    """Return case counts grouped by day for the last 14 days."""
    import calendar
    from datetime import timedelta

    cases = list_cases()
    now = datetime.now(timezone.utc)
    days = []
    for i in range(13, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        days.append(day)

    by_day = {d: {"created": 0, "resolved": 0, "total": 0} for d in days}
    for c in cases:
        created = (c.get("created_at") or "")[:10]
        if created in by_day:
            by_day[created]["created"] += 1
            by_day[created]["total"] += 1
        resolved = (c.get("updated_at") or "")[:10]
        if resolved in by_day and c.get("status") in ("resolved", "closed", "rejected"):
            by_day[resolved]["resolved"] += 1

    return {"days": [{"date": d, **by_day[d]} for d in days]}


@app.get("/wazuh-api/autopilot/cases")
def autopilot_cases():
    cases = list_cases()
    affected = []
    for c in cases:
        affected.append({
            "id": c.get("id", ""),
            "title": c.get("title", ""),
            "severity": c.get("severity", "low"),
            "status": c.get("status", "open"),
            "alert_count": len(c.get("alert_ids", [])),
            "mitre": {"technique_id": c.get("mitre_technique", "")},
            "ai_analysis": c.get("ai_analysis", ""),
            "confidence": c.get("confidence", 0.5),
            "updated_at": c.get("updated_at", ""),
            "created_at": c.get("created_at", ""),
        })
    return {"affected_items": affected}


@app.get("/wazuh-api/autopilot/cases/{case_id}")
def autopilot_case_detail(case_id: str):
    c = get_case(case_id)
    if c:
        return c
    raise HTTPException(status_code=404, detail="Case not found")


@app.post("/wazuh-api/autopilot/cases/{case_id}/approve")
def autopilot_approve(case_id: str):
    now = datetime.now(timezone.utc).isoformat()
    c = get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    events = c.get("events", [])
    if isinstance(events, str):
        try:
            events = json.loads(events)
        except Exception:
            events = []
    events.append({"type": "approved", "timestamp": now, "detail": "Approved by SOC operator"})
    update_case(case_id, {"status": "approved", "events": events})
    return {"status": "ok", "case": {"id": case_id, "status": "approved"}}


SUPPRESS_FILE = BASE_DIR / "ai_suppressions.json"


def _load_suppressions() -> list:
    if not SUPPRESS_FILE.exists():
        return []
    try:
        return json.loads(SUPPRESS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_suppressions(s: list):
    SUPPRESS_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")


def _add_suppression(case: dict):
    patterns = _load_suppressions()
    entry = {
        "title": (case.get("title") or "").strip(),
        "source": "",
        "rule_id": 0,
        "suppressed_at": datetime.now(timezone.utc).isoformat(),
    }
    entities = case.get("entities", [])
    if isinstance(entities, str):
        try:
            entities = json.loads(entities)
        except Exception:
            entities = []
    for e in entities:
        if isinstance(e, dict):
            src = e.get("source") or e.get("value", "")
            if src and src != "unknown":
                entry["source"] = src
                break
    patterns.append(entry)
    _save_suppressions(patterns)
    logger.info("Added suppression: %s — %d patterns total", entry["title"], len(patterns))


def _is_suppressed(alert: dict) -> bool:
    title = (alert.get("title") or "").strip().lower()
    source = (alert.get("source") or "").strip().lower()
    for p in _load_suppressions():
        pt = p.get("title", "").lower()
        ps = p.get("source", "").lower()
        if pt and pt in title:
            return True
        if ps and source and ps in source:
            return True
        if ps and source and source in ps:
            return True
    return False


@app.post("/wazuh-api/autopilot/cases/{case_id}/reject")
def autopilot_reject(case_id: str):
    c = get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    now = datetime.now(timezone.utc).isoformat()
    events = c.get("events", [])
    if isinstance(events, str):
        try:
            events = json.loads(events)
        except Exception:
            events = []
    events.append({"type": "rejected", "timestamp": now, "detail": "Rejected by SOC operator"})
    update_case(case_id, {"status": "rejected", "events": events})
    _add_suppression(c)
    return {"status": "ok", "case": {"id": case_id, "status": "rejected"}, "suppressed": True}


@app.post("/wazuh-api/autopilot/cases/{case_id}/execute")
def autopilot_execute(case_id: str):
    c = get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    if c.get("status") != "approved":
        raise HTTPException(status_code=400, detail="Case must be approved before execution")

    from ai_remediate import execute_case
    import threading

    def _run():
        try:
            results = execute_case(c)
            now = datetime.now(timezone.utc).isoformat()
            events = c.get("events", [])
            if isinstance(events, str):
                try:
                    events = json.loads(events)
                except Exception:
                    events = []
            for r in results:
                r_status = "ok" if r.get("success") else r.get("error", "failed")
                events.append({
                    "type": "executed" if r.get("success") else "failed",
                    "timestamp": now,
                    "detail": f"{r.get('action', 'unknown')} → {r.get('target', '')}: {r_status}",
                })
            update_case(case_id, {
                "status": "in_progress",
                "events": events,
                "actions": results,
            })
        except Exception as e:
            logger.error("Execute error for case %s: %s", case_id, e)

    threading.Thread(target=_run, daemon=True).start()

    return {"status": "ok", "message": "Execution triggered, running in background"}


def _fetch_open_alerts() -> list[dict]:
    """Fetch open alerts from Wazuh SIEM and internal monitoring."""
    alerts = []

    # 1. Wazuh SIEM alerts (levels 0-15, the main SOC data)
    try:
        token = _wazuh_soc_token["value"] or _wazuh_soc_login()
        if token:
            resp = requests.get(
                f"{WAZUH_SOC_API_BASE}/events",
                params={"size": 200},
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            if resp.ok:
                data = resp.json()
                wazuh_alerts = data.get("data", {}).get("affected_items", data.get("affected_items", []))
                for a in wazuh_alerts:
                    alerts.append({
                        "id": a.get("id", ""),
                        "level": a.get("level", 0),
                        "title": a.get("description", ""),
                        "description": a.get("description", ""),
                        "source": a.get("agent", {}).get("name", "unknown"),
                        "rule_id": a.get("rule_id", 0),
                        "similar_count": 0,
                        "timestamp": a.get("timestamp", ""),
                    })
                logger.info("Fetched %d Wazuh alerts", len(wazuh_alerts))
    except Exception as e:
        logger.error("Failed to fetch Wazuh alerts: %s", e)

    # 2. Internal monitoring alerts (port 8000)
    try:
        api_key = os.getenv("MISSION_API_KEY", "mission-test-key-123")
        resp = requests.get(
            "http://127.0.0.1:8000/api/v1/alerts",
            params={"status": "OPEN,ACKNOWLEDGED", "limit": 200},
            headers={"x-api-key": api_key},
            timeout=30,
        )
        if resp.ok:
            data = resp.json()
            for a in data.get("alerts", []):
                ad = a.get("alert", a)
                alerts.append({
                    "id": ad.get("id", ""),
                    "level": ad.get("level", 0),
                    "title": ad.get("title", ad.get("message", "")),
                    "description": ad.get("message", ad.get("description", "")),
                    "source": ad.get("source", a.get("site", {}).get("site_name", "unknown")),
                    "rule_id": ad.get("rule_id", 0),
                    "similar_count": 0,
                    "timestamp": ad.get("created_at", ""),
                })
    except Exception as e:
        logger.error("Failed to fetch internal alerts: %s", e)

    return alerts


def _fetch_processed_alert_ids() -> set:
    """Get set of alert IDs already triaged (from audit log or case alert_ids)."""
    processed = set()
    try:
        for c in list_cases():
            for aid in c.get("alert_ids", []):
                if aid:
                    processed.add(str(aid))
    except Exception:
        pass
    try:
        import json as _json
        from ai_resolver import AUDIT_FILE
        if AUDIT_FILE.exists():
            for entry in _json.loads(AUDIT_FILE.read_text(encoding="utf-8")):
                aid = entry.get("alert_id", "")
                if aid:
                    processed.add(str(aid))
    except Exception:
        pass
    return processed


def ai_scan_and_generate():
    """AI-powered scan cycle — triages new alerts and routes to auto-resolve or case."""
    new_cases = 0
    auto_resolved = 0

    processed_ids = _fetch_processed_alert_ids()
    alerts = _fetch_open_alerts()

    if not alerts:
        logger.info("AI scan: no open alerts to process")
        return {"new_cases": 0, "auto_resolved": 0}

    new_alerts = []
    for a in alerts:
        alert_data = a.get("alert", a)
        aid = str(alert_data.get("id", ""))
        if aid and aid not in processed_ids:
            new_alerts.append(alert_data)

    if not new_alerts:
        logger.info("AI scan: no new alerts to process")
        return {"new_cases": 0, "auto_resolved": 0}

    logger.info("AI scan: processing %d new alerts", len(new_alerts))

    # Prioritize high-level alerts, limit batch size
    new_alerts.sort(key=lambda a: a.get("level", 0), reverse=True)
    batch = [a for a in new_alerts if a.get("level", 0) >= 12][:5]  # max 5 high-sev per cycle
    if not batch:
        batch = new_alerts[:3]  # fallback to first 3 if none high-sev
    logger.info("AI scan: triaging %d alerts this cycle (levels: %s)",
                len(batch), [a.get("level", 0) for a in batch])

    # Group alerts by source + time window (10 min)
    from collections import defaultdict
    groups = defaultdict(list)
    for a in batch:
        if _is_suppressed(a):
            logger.info("Skipping suppressed alert %s: %s", a.get("id", "?"), a.get("title", "")[:60])
            continue
        groups[a.get("source", "unknown")].append(a)

    # Merge groups that share at least one alert within 10 min of each other
    merged = []
    for source, alerts in groups.items():
        alerts.sort(key=lambda a: a.get("timestamp", ""))
        window_start = 0
        for i in range(1, len(alerts)):
            t1 = alerts[window_start].get("timestamp", "")
            t2 = alerts[i].get("timestamp", "")
            if t1 and t2:
                try:
                    from datetime import datetime as _dt
                    dt1 = _dt.fromisoformat(t1.replace("Z", "+00:00"))
                    dt2 = _dt.fromisoformat(t2.replace("Z", "+00:00"))
                    if (dt2 - dt1).total_seconds() > 600:  # 10 min window
                        merged.append(alerts[window_start:i])
                        window_start = i
                except Exception:
                    pass
        merged.append(alerts[window_start:])

    for group in merged:
        if not group:
            continue
        max_level = max(a.get("level", 0) for a in group)
        group.sort(key=lambda a: a.get("level", 0), reverse=True)
        primary = group[0]

        try:
            analysis = triage_alert({
                "id": primary.get("id", ""),
                "level": max_level,
                "title": f"{len(group)} related alerts — {primary.get('title', '')}",
                "description": f"Alert cluster: {len(group)} events from {primary.get('source', 'unknown')}. {primary.get('description', '')}",
                "source": primary.get("source", "unknown"),
                "rule_id": primary.get("rule_id", 0),
                "similar_count": len(group) - 1,
            })

            confidence = analysis.get("confidence", 0.5)
            recommended_action = analysis.get("recommended_action", "escalate")

            if max_level <= 7:
                for a in group:
                    from ai_resolver import log_action as _log
                    _log(a.get("id", ""), a.get("title", ""), a.get("level", 0),
                         "auto_resolve", confidence, analysis.get("analysis", ""))
                auto_resolved += len(group)
            elif max_level <= 11:
                if recommended_action == "escalate":
                    cid = create_case(group, analysis)
                    if cid:
                        new_cases += 1
                else:
                    for a in group:
                        from ai_resolver import log_action as _log
                        _log(a.get("id", ""), a.get("title", ""), a.get("level", 0),
                             "auto_resolve", confidence, analysis.get("analysis", ""))
                    auto_resolved += len(group)
            else:
                cid = create_case(group, analysis)
                if cid:
                    new_cases += 1
                    # Auto-execute for critical alerts with high confidence
                    if max_level >= 15 and confidence >= 0.9:
                        from ai_remediate import execute_case
                        new_case = get_case(cid)
                        if new_case:
                            results = execute_case(new_case)
                            update_case(cid, {"status": "in_progress",
                                              "actions": results})
                            from ai_resolver import log_action as _log
                            _log(primary.get("id", ""), primary.get("title", ""), max_level,
                                 "auto_executed", confidence,
                                 f"Auto-remediation: {len(results)} actions")
                            logger.info("Auto-executed case %s (%d actions)",
                                        cid, len(results))

        except Exception as e:
            logger.error("AI scan: error processing alert %s: %s",
                         alert.get("id", "?"), e)

    logger.info("AI scan complete: %d cases created, %d auto-resolved",
                new_cases, auto_resolved)
    return {"new_cases": new_cases, "auto_resolved": auto_resolved}


# Schedule AI scan every 5 minutes
AUTOPILOT_SCAN_INTERVAL = 300


@app.on_event("startup")
def _start_autopilot_scanner():
    import threading

    def _scanner_loop():
        while True:
            time.sleep(AUTOPILOT_SCAN_INTERVAL)
            try:
                ai_scan_and_generate()
            except Exception as exc:
                logger.error("AI scanner error: %s", exc)

    t = threading.Thread(target=_scanner_loop, daemon=True)
    t.start()
    logger.info("AI Autopilot scanner started (interval=%ds)", AUTOPILOT_SCAN_INTERVAL)

    # Start SOC Agent daemon (Telegram + auto-triage)
    try:
        from soc_agent import start_daemon
        start_daemon()
    except ImportError:
        logger.warning("soc_agent.py not found — Telegram/auto-triage disabled")
    except Exception as exc:
        logger.error("SOC Agent daemon failed to start: %s", exc)


@app.post("/wazuh-api/autopilot/scan")
def autopilot_manual_scan():
    result = ai_scan_and_generate()
    return {"status": "ok", "result": result}


# ── SOC Agent / Telegram Endpoints ────────────────────────────────────────

@app.get("/wazuh-api/soc-agent/status")
def soc_agent_status():
    from soc_agent import TELEGRAM_ENABLED, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    return {
        "telegram_enabled": TELEGRAM_ENABLED,
        "telegram_configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
        "bot_token_set": bool(TELEGRAM_BOT_TOKEN),
        "chat_id_set": bool(TELEGRAM_CHAT_ID),
    }


@app.post("/wazuh-api/soc-agent/triage")
def soc_agent_triage():
    from soc_agent import run_triage_cycle
    return run_triage_cycle()


@app.post("/wazuh-api/soc-agent/test")
def soc_agent_test():
    from soc_agent import send_test_notification
    result = send_test_notification()
    return result


@app.post("/wazuh-api/soc-agent/digest")
def soc_agent_digest():
    from soc_agent import _send_digest
    ok = _send_digest()
    return {"status": "ok" if ok else "skipped", "message": "Digest sent to Telegram" if ok else "Already sent today or Telegram disabled"}


# ── SOC Agent Dashboard API ──────────────────────────────────────────────

_AGENT_LOG = []  # [(timestamp, message), ...]


def _agent_log(msg: str) -> None:
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
    _AGENT_LOG.append((now, msg))
    if len(_AGENT_LOG) > 50:
        _AGENT_LOG.pop(0)


@app.get("/api/soc-agent/status")
def api_soc_agent_status(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    from soc_agent import TELEGRAM_ENABLED, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    return {
        "telegram_enabled": TELEGRAM_ENABLED,
        "telegram_configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
        "bot_token_set": bool(TELEGRAM_BOT_TOKEN),
        "chat_id_set": bool(TELEGRAM_CHAT_ID),
    }


@app.get("/api/soc-agent/alerts")
def api_soc_agent_alerts(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    try:
        from soc_agent import _get_alerts_direct
        alerts = _get_alerts_direct(limit=200)
        total = len(alerts)
        critical = len([a for a in alerts if (a.get("severity") or "").upper() == "CRITICAL"])
        high = len([a for a in alerts if (a.get("severity") or "").upper() == "HIGH"])
        medium = len([a for a in alerts if (a.get("severity") or "").upper() == "MEDIUM"])
        low = len([a for a in alerts if (a.get("severity") or "").upper() == "LOW"])
        _agent_log(f"Fetched {total} alerts from Supabase")
        return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}
    except Exception as exc:
        _agent_log(f"Alert fetch failed: {exc}")
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": str(exc)}


@app.get("/api/soc-agent/alert-list")
def api_soc_agent_alert_list(request: Request, limit: int = 10):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    try:
        from soc_agent import _get_alerts_direct, _get_sites_direct
        alerts = _get_alerts_direct(limit=limit)
        sites = _get_sites_direct()
        enriched = []
        for a in alerts:
            dev = None
            if a.get("device_id"):
                try:
                    from soc_agent import _get_device_direct
                    dev = _get_device_direct(str(a["device_id"]))
                except Exception:
                    pass
            enriched.append({
                "id": a.get("id"),
                "title": a.get("title"),
                "message": a.get("message"),
                "severity": a.get("severity"),
                "alert_type": a.get("alert_type"),
                "status": a.get("status"),
                "count": a.get("count"),
                "first_seen_at": a.get("first_seen_at"),
                "last_seen_at": a.get("last_seen_at"),
                "site": sites.get(str(a.get("site_id", "")), {}),
                "device": dev,
            })
        _agent_log(f"Returned {len(enriched)} alerts with device info")
        return {"alerts": enriched}
    except Exception as exc:
        _agent_log(f"Alert list failed: {exc}")
        return {"alerts": [], "error": str(exc)}


@app.get("/api/soc-agent/history")
def api_soc_agent_history(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    from soc_agent import _ESCALATED_ALERTS, DIGEST_HOUR
    digest_file = os.path.join(os.path.dirname(__file__), "digest_snapshot.json")
    last_digest = None
    if os.path.exists(digest_file):
        try:
            import json as _json
            last_digest = _json.load(open(digest_file)).get("date", "unknown")
        except Exception:
            pass
    return {
        "escalations": len(_ESCALATED_ALERTS),
        "escalation_threshold": int(os.getenv("ESCALATION_THRESHOLD_MINUTES", "30")),
        "last_digest": last_digest,
        "digest_hour": DIGEST_HOUR,
        "log": [{"t": t, "msg": m} for t, m in _AGENT_LOG[-20:]],
    }


@app.get("/soc-agent-dashboard.html", response_class=HTMLResponse)
def soc_agent_dashboard():
    return read_html("soc-agent-dashboard.html")


# ── Server-Sent Events for live dashboard updates ──────────────────────

@app.get("/api/events/stream")
async def api_sse_stream(request: Request):
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            try:
                yield f"event: ping\ndata: {json.dumps({'time': datetime.now(timezone.utc).isoformat()})}\n\n"
            except Exception:
                break
            await asyncio.sleep(30)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


# ── Backup / Export ──────────────────────────────────────────────────────

@app.get("/api/backup/projects")
def api_backup_projects(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    import json as _json
    projects_file = BASE_DIR / "projects.json"
    if not projects_file.exists():
        return JSONResponse({"error": "no projects data"}, status_code=404)
    data = _json.loads(projects_file.read_text(encoding="utf-8"))
    autopilot_file = BASE_DIR / "autopilot_cases.json"
    if autopilot_file.exists():
        data["autopilot_cases"] = _json.loads(autopilot_file.read_text(encoding="utf-8"))
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": "attachment; filename=mission_control_backup.json"},
    )


# ── Alert Actions & Metrics ──────────────────────────────────────────────

@app.post("/api/alert/{alert_id}/{action}")
def api_alert_action(alert_id: str, action: str, request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if action not in ("acknowledge", "resolve"):
        raise HTTPException(status_code=400, detail="Invalid action. Use 'acknowledge' or 'resolve'.")
    from soc_agent import _update_alert_status as _uas
    new_status = "ACKNOWLEDGED" if action == "acknowledge" else "RESOLVED"
    message = _uas(alert_id, new_status)
    return {"status": "ok", "message": message}


@app.get("/api/alert/metrics")
def api_alert_metrics(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    from soc_agent import _supabase_get
    days = [1, 7, 30]
    result = {}
    for d in days:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=d)).isoformat()
        alerts = _supabase_get("mc_alerts", {
            "first_seen_at": f"gte.{cutoff}",
            "select": "severity,first_seen_at",
            "limit": "5000",
        })
        if alerts is None:
            alerts = []
        total = len(alerts)
        critical = len([a for a in alerts if (a.get("severity") or "").upper() == "CRITICAL"])
        high = len([a for a in alerts if (a.get("severity") or "").upper() == "HIGH"])
        # Group by day
        from collections import Counter
        day_counts = Counter()
        for a in alerts:
            day = (a.get("first_seen_at") or "")[:10]
            if day:
                day_counts[day] += 1
        result[f"{d}d"] = {
            "total": total,
            "critical": critical,
            "high": high,
            "by_day": [{"date": k, "count": v} for k, v in sorted(day_counts.items())],
        }
    return result


@app.get("/alerts.html", response_class=HTMLResponse)
def alerts_page():
    return read_html("alerts.html")


# ── Natural Language Search ──────────────────────────────────────────────

NL_INTENTS = [
    (r"(?i)(offline|down|unreachable)\s+(devices?|agents?|hosts?)", "alerts_device_offline"),
    (r"(?i)(critical|high)\s+(alerts?|issues?|incidents?)", "alerts_critical_high"),
    (r"(?i)(show|list|get)\s+(open|active)\s+alerts?", "alerts_open"),
    (r"(?i)(how many|count)\s+(devices?|hosts?)", "devices_count"),
    (r"(?i)(how many|count)\s+(alerts?|incidents?)", "alerts_count"),
    (r"(?i)(device|host|ip)\s+(\d+\.\d+\.\d+\.\d+)", "device_by_ip"),
    (r"(?i)(site|location)\s+(\w+)", "site_summary"),
    (r"(?i)(classif|label|type)\s+(unknown|unclassified)", "classification_needs"),
    (r"(?i)(health|status|summary|overview)", "overview"),
    (r"(?i)(agent|endpoint)s?\s+(status|health)", "agent_status"),
    (r"(?i)(recent|new)\s+(device|host)s?", "new_devices"),
    (r"(?i)(help|commands?|what can|what do)", "help"),
]


def _nl_search(query: str) -> dict:
    intent = None
    params = {}
    for pattern, intent_name in NL_INTENTS:
        m = re.search(pattern, query.strip())
        if m:
            intent = intent_name
            params = m.groupdict() if m.groupdict() else {}
            # Extract positional groups
            groups = m.groups()
            if intent_name == "device_by_ip" and len(groups) >= 2:
                params["ip"] = groups[-1]
            elif intent_name == "site_summary" and len(groups) >= 2:
                params["site"] = groups[-1]
            break

    if not intent:
        return {"intent": None, "query": query, "message": "I didn't understand that. Try: 'show offline devices', 'critical alerts', 'site health', or 'help'."}

    results = {}
    message = ""

    if intent == "alerts_device_offline":
        try:
            r = requests.get("http://127.0.0.1:8000/api/v1/alerts", params={"status": "OPEN,ACKNOWLEDGED", "severity": "CRITICAL,HIGH", "limit": "20"}, headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                alerts = d.get("alerts", d) if isinstance(d, dict) else []
                offline = [a for a in alerts if "OFFLINE" in (a.get("alert", a).get("alert_type", "") or "").upper()]
                results = {"type": "offline_devices", "count": len(offline), "items": [{"title": a.get("alert", a).get("title", ""), "severity": a.get("alert", a).get("severity", ""), "site": (a.get("site", {}) or {}).get("site_name", "")} for a in offline[:10]]}
                message = f"Found {len(offline)} offline device alerts." if offline else "No devices currently marked offline."
            else:
                message = "Could not fetch alert data."
        except Exception as e:
            message = f"Error fetching alerts: {e}"

    elif intent == "alerts_critical_high":
        try:
            r = requests.get("http://127.0.0.1:8000/api/v1/alerts", params={"status": "OPEN,ACKNOWLEDGED", "severity": "CRITICAL,HIGH", "limit": "20"}, headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                alerts = d.get("alerts", d) if isinstance(d, dict) else []
                results = {"type": "critical_alerts", "count": len(alerts), "items": [{"title": a.get("alert", a).get("title", ""), "severity": a.get("alert", a).get("severity", ""), "site": (a.get("site", {}) or {}).get("site_name", "")} for a in alerts[:15]]}
                message = f"{len(alerts)} critical or high severity alerts." if alerts else "No critical or high alerts."
            else:
                message = "Could not fetch alert data."
        except Exception as e:
            message = f"Error: {e}"

    elif intent == "alerts_open":
        try:
            r = requests.get("http://127.0.0.1:8000/api/v1/alerts", params={"status": "OPEN", "limit": "20"}, headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                alerts = d.get("alerts", d) if isinstance(d, dict) else []
                results = {"type": "open_alerts", "count": len(alerts), "items": [{"title": a.get("alert", a).get("title", ""), "severity": a.get("alert", a).get("severity", ""), "site": (a.get("site", {}) or {}).get("site_name", "")} for a in alerts[:15]]}
                message = f"{len(alerts)} open alerts."
            else:
                message = "Could not fetch alert data."
        except Exception as e:
            message = f"Error: {e}"

    elif intent == "overview":
        try:
            r = requests.get("http://127.0.0.1:8000/api/v1/dashboard/summary", headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                c = d.get("counts", {})
                results = {"type": "overview", "devices_total": c.get("devices_total", 0), "devices_online": c.get("devices_online", 0), "devices_offline": c.get("devices_offline", 0), "alerts_open": c.get("alerts_open", 0), "agents_online": c.get("agents_online", 0)}
                message = f"{c.get('devices_total', 0)} devices ({c.get('devices_online', 0)} online, {c.get('devices_offline', 0)} offline), {c.get('alerts_open', 0)} open alerts, {c.get('agents_online', 0)} agents online."
            else:
                message = "Could not fetch overview."
        except Exception as e:
            message = f"Error: {e}"

    elif intent == "devices_count":
        try:
            r = requests.get("http://127.0.0.1:8000/api/v1/dashboard/summary", headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                c = d.get("counts", {})
                results = {"type": "devices_count", "total": c.get("devices_total", 0), "online": c.get("devices_online", 0), "offline": c.get("devices_offline", 0)}
                message = f"Total devices: {c.get('devices_total', 0)} ({c.get('devices_online', 0)} online, {c.get('devices_offline', 0)} offline)."
            else:
                message = "Could not fetch device data."
        except Exception as e:
            message = f"Error: {e}"

    elif intent == "alerts_count":
        try:
            r = requests.get("http://127.0.0.1:8000/api/v1/alerts", params={"status": "OPEN,ACKNOWLEDGED", "limit": "1"}, headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                counts = d.get("counts", {}) if isinstance(d, dict) else {}
                total = counts.get("total", d.get("total", 0))
                results = {"type": "alerts_count", "total": total}
                message = f"{total} total open or acknowledged alerts."
            else:
                message = "Could not fetch alert data."
        except Exception as e:
            message = f"Error: {e}"

    elif intent == "device_by_ip":
        ip = params.get("ip", "")
        if ip:
            try:
                r = requests.get(f"http://127.0.0.1:8000/api/v1/admin/devices", params={}, headers={"x-api-key": MONITORING_API_KEY}, timeout=8)
                if r.status_code == 200:
                    devices = r.json().get("devices", [])
                    match = [d for d in devices if d.get("ip_address") == ip]
                    if match:
                        d = match[0]
                        results = {"type": "device_detail", "ip": ip, "hostname": d.get("hostname", ""), "vendor": d.get("vendor", ""), "device_type": d.get("device_type", ""), "status": d.get("status", ""), "friendly_name": d.get("friendly_name", "")}
                        message = f"Device {ip}: {d.get('friendly_name') or d.get('hostname') or 'Unnamed'}, type={d.get('device_type', 'Unknown')}, status={d.get('status', 'Unknown')}."
                    else:
                        message = f"No device found with IP {ip}."
                else:
                    message = "Could not fetch device data."
            except Exception as e:
                message = f"Error: {e}"
        else:
            message = "Please specify an IP address."

    elif intent == "site_summary":
        site = params.get("site", "")
        if site:
            message = f"Looking up site '{site}' — try the All Sites Dashboard for detailed site info."
            results = {"type": "site_hint", "site": site}
        else:
            message = "Please specify a site name."

    elif intent == "help":
        results = {"type": "help"}
        message = "I can answer questions like:\n• 'show offline devices'\n• 'critical alerts'\n• 'how many devices'\n• 'device 192.168.1.1'\n• 'site health'\n• 'classification needs'\n• 'agent status'"

    else:
        message = "That query isn't supported yet. Try: 'offline devices', 'critical alerts', 'site health', or 'help'."

    return {"intent": intent, "query": query, "message": message, "results": results}


@app.post("/wazuh-api/nl/search")
async def nl_search(request: Request):
    body = await request.json()
    query = (body.get("query") or "").strip()
    if not query:
        return {"intent": None, "message": "Please type a question.", "results": {}}
    return _nl_search(query)


@app.api_route("/wazuh-api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def wazuh_api_proxy(path: str, request: Request):
    target_url = f"{WAZUH_SOC_API_BASE}/{path}"
    try:
        body = await request.body()
        headers = {}
        ct = request.headers.get("content-type")
        if ct:
            headers["Content-Type"] = ct
        # Inject SOC bearer token
        token = _wazuh_soc_token["value"] or _wazuh_soc_login()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.request(
            method=request.method,
            url=target_url,
            params=dict(request.query_params),
            data=body if body else None,
            headers=headers,
            timeout=60,
        )
        # Re-auth on 401 and retry once
        if resp.status_code == 401:
            token = _wazuh_soc_login()
            if token:
                headers["Authorization"] = f"Bearer {token}"
                resp = requests.request(
                    method=request.method,
                    url=target_url,
                    params=dict(request.query_params),
                    data=body if body else None,
                    headers=headers,
                    timeout=60,
                )
        excluded = {"content-encoding", "transfer-encoding", "content-length"}
        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
        from starlette.responses import Response
        return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)
    except Exception as e:
        return JSONResponse({"error": f"Wazuh SOC API unreachable: {str(e)}"}, status_code=502)


async def proxy_request(base_url: str, path: str, request: Request, error_message: str):
    target_url = f"{base_url}/{path}"

    try:
        body = await request.body()

        incoming_headers = {}
        # Inject API key for monitoring API proxy
        if base_url == MONITORING_API_BASE and MONITORING_API_KEY:
            incoming_headers["X-API-Key"] = MONITORING_API_KEY
        content_type = request.headers.get("content-type")
        if content_type:
            incoming_headers["Content-Type"] = content_type

        response = requests.request(
            method=request.method,
            url=target_url,
            params=dict(request.query_params),
            data=body if body else None,
            headers=incoming_headers,
            timeout=60,
        )

        response_content_type = response.headers.get("content-type", "")

        if "application/json" in response_content_type.lower():
            try:
                return JSONResponse(content=response.json(), status_code=response.status_code)
            except Exception:
                return JSONResponse(content={"raw": response.text}, status_code=response.status_code)

        passthrough_headers = {}

        content_disposition = response.headers.get("content-disposition")
        if content_disposition:
            passthrough_headers["Content-Disposition"] = content_disposition

        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response_content_type or "application/octet-stream",
            headers=passthrough_headers,
        )

    except requests.exceptions.RequestException as e:
        return JSONResponse(
            status_code=502,
            content={
                "detail": error_message,
                "error": str(e),
                "target": target_url
            }
        )


# ── 2FA Routes ────────────────────────────────────────────────────────────────

@app.get("/2fa-verify", response_class=HTMLResponse)
def twofa_verify_get(request: Request):
    if not _get_2fa_pending_user(request):
        return RedirectResponse(url="/login", status_code=302)
    page = read_html("2fa-verify.html")
    if isinstance(page, HTMLResponse):
        html = page.body.decode()
        html = html.replace("__ERROR_CLASS__", "").replace("__ERROR__", "")
        return HTMLResponse(content=html)
    return page


@app.post("/2fa-verify")
async def twofa_verify_post(request: Request):
    pending_user = _get_2fa_pending_user(request)
    if not pending_user:
        return RedirectResponse(url="/login", status_code=302)

    form = await request.form()
    code = str(form.get("code", "")).strip()

    user = next((u for u in _load_users() if u.get("username") == pending_user and u.get("active", True)), None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    if _totp_check(user.get("totp_secret", ""), code):
        token = _serializer.dumps({"user": pending_user})
        resp = RedirectResponse(url="/index-platform.html", status_code=302)
        resp.delete_cookie(_2FA_PENDING_COOKIE)
        resp.set_cookie(_COOKIE_NAME, token, max_age=_COOKIE_MAX_AGE, httponly=True, samesite="lax")
        return resp

    page = read_html("2fa-verify.html")
    if isinstance(page, HTMLResponse):
        html = page.body.decode()
        html = html.replace("__ERROR_CLASS__", "visible")
        html = html.replace("__ERROR__", "Invalid code. Please try again.")
        return HTMLResponse(content=html, status_code=401)
    return page


@app.get("/2fa-setup.html", response_class=HTMLResponse)
def twofa_setup_page():
    return read_html("2fa-setup.html")


@app.get("/api/2fa/status")
def twofa_status(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    return {"enabled": bool(user.get("totp_enabled")), "has_secret": bool(user.get("totp_secret"))}


@app.post("/api/2fa/generate")
def twofa_generate(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    secret = _totp_make_secret()
    uri    = _totp_uri(secret, user["username"])
    qr_b64 = _totp_qr_b64(uri)
    # Store pending secret (not yet active)
    users = _load_users()
    for u in users:
        if u["user_id"] == user["user_id"]:
            u["totp_secret_pending"] = secret
            break
    _save_users(users)
    return {"secret": secret, "qr_code": f"data:image/png;base64,{qr_b64}", "uri": uri}


@app.post("/api/2fa/activate")
async def twofa_activate(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    code = str(body.get("code", "")).strip()
    pending_secret = user.get("totp_secret_pending", "")
    if not pending_secret:
        raise HTTPException(status_code=400, detail="No pending setup. Click Enable 2FA first.")
    if not _totp_check(pending_secret, code):
        raise HTTPException(status_code=400, detail="Invalid code. Try again.")
    users = _load_users()
    for u in users:
        if u["user_id"] == user["user_id"]:
            u["totp_secret"]  = pending_secret
            u["totp_enabled"] = True
            u.pop("totp_secret_pending", None)
            break
    _save_users(users)
    return {"success": True}


@app.post("/api/2fa/disable")
async def twofa_disable(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    code = str(body.get("code", "")).strip()
    if not user.get("totp_enabled") or not user.get("totp_secret"):
        raise HTTPException(status_code=400, detail="2FA is not enabled on this account.")
    if not _totp_check(user["totp_secret"], code):
        raise HTTPException(status_code=400, detail="Invalid code.")
    users = _load_users()
    for u in users:
        if u["user_id"] == user["user_id"]:
            u["totp_enabled"] = False
            u.pop("totp_secret", None)
            u.pop("totp_secret_pending", None)
            break
    _save_users(users)
    return {"success": True}


@app.delete("/api/2fa/{user_id}")
def twofa_reset_user(user_id: str, request: Request):
    """Admin only: reset another user's 2FA."""
    caller = _get_authenticated_user(request)
    if not caller or caller.get("role") != "admin":
        return JSONResponse({"error": "admin only"}, status_code=403)
    users = _load_users()
    found = False
    for u in users:
        if u["user_id"] == user_id:
            u["totp_enabled"] = False
            u.pop("totp_secret", None)
            u.pop("totp_secret_pending", None)
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail="User not found")
    _save_users(users)
    return {"success": True}

# ── Project Manager API ─────────────────────────────────────────────────────
PROJECTS_FILE = BASE_DIR / "projects.json"


def _load_projects() -> dict:
    if not PROJECTS_FILE.exists():
        return {"projects": []}
    try:
        return json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"projects": []}


def _save_projects(data: dict) -> None:
    PROJECTS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _get_project(project_id: str) -> dict | None:
    for p in _load_projects().get("projects", []):
        if p["id"] == project_id:
            return p
    return None


def _make_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


@app.get("/api/projects")
def api_list_projects(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    data = _load_projects()
    # Return summary (no task details) for list view
    summary = []
    for p in data.get("projects", []):
        tasks = p.get("tasks", [])
        total = len(tasks)
        done = len([t for t in tasks if t.get("status") == "done"])
        summary.append({
            "id": p["id"],
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "total_tasks": total,
            "done_tasks": done,
            "progress": round(done / total * 100, 1) if total else 0,
            "created_at": p.get("created_at", ""),
        })
    return {"projects": summary}


@app.post("/api/projects")
async def api_create_project(request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Project name is required")
    data = _load_projects()
    now = datetime.now(timezone.utc).isoformat()
    project = {
        "id": _make_id(),
        "name": name,
        "description": (body.get("description") or "").strip(),
        "created_at": now,
        "updated_at": now,
        "tasks": [],
        "status_values": ["not_started", "in_progress", "blocked", "review", "done"],
    }
    data["projects"].append(project)
    _save_projects(data)
    return {"status": "ok", "project": {"id": project["id"], "name": project["name"]}}


@app.get("/api/projects/{project_id}")
def api_get_project(project_id: str, request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    project = _get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@app.post("/api/projects/{project_id}/tasks")
async def api_create_task(project_id: str, request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    title = (body.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Task title is required")
    data = _load_projects()
    project = None
    for p in data.get("projects", []):
        if p["id"] == project_id:
            project = p
            break
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    now = datetime.now(timezone.utc).isoformat()
    task = {
        "id": _make_id(),
        "title": title,
        "description": (body.get("description") or "").strip(),
        "status": "not_started",
        "owner": (body.get("owner") or user.get("username", "")).strip(),
        "priority": (body.get("priority") or "medium").strip(),
        "target_date": body.get("target_date"),
        "phase": (body.get("phase") or "").strip(),
        "dependencies": body.get("dependencies", []),
        "proof": [],
        "notes": "",
        "created_at": now,
        "updated_at": now,
    }
    project["tasks"].append(task)
    project["updated_at"] = now
    _save_projects(data)
    return {"status": "ok", "task": task}


@app.patch("/api/tasks/{task_id}")
async def api_update_task(task_id: str, request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    data = _load_projects()
    now = datetime.now(timezone.utc).isoformat()
    for p in data.get("projects", []):
        for t in p.get("tasks", []):
            if t["id"] == task_id:
                allowed = {"status", "title", "description", "owner", "priority", "target_date", "phase", "notes", "proof"}
                for key, value in body.items():
                    if key in allowed:
                        t[key] = value
                t["updated_at"] = now
                p["updated_at"] = now
                _save_projects(data)
                return {"status": "ok", "task": t}
    raise HTTPException(status_code=404, detail="Task not found")


@app.delete("/api/tasks/{task_id}")
def api_delete_task(task_id: str, request: Request):
    user = _get_authenticated_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    data = _load_projects()
    for p in data.get("projects", []):
        for i, t in enumerate(p.get("tasks", [])):
            if t["id"] == task_id:
                p["tasks"].pop(i)
                p["updated_at"] = datetime.now(timezone.utc).isoformat()
                _save_projects(data)
                return {"status": "ok", "deleted": task_id}
    raise HTTPException(status_code=404, detail="Task not found")


@app.get("/project-manager.html", response_class=HTMLResponse)
def project_manager_page():
    return read_html("project-manager.html")


@app.get("/project-tracker.html", response_class=HTMLResponse)
def project_tracker_dash():
    return read_html("project-tracker/dashboard/index.html")

@app.get("/project_tracker.html", response_class=HTMLResponse)
def project_tracker_underscore():
    return read_html("project_tracker.html")


@app.get("/project-tracker/tasks.json")
def project_tracker_tasks_json():
    tracker_file = BASE_DIR / "project-tracker" / "tasks.json"
    if not tracker_file.exists():
        return JSONResponse({"error": "tracker_not_found"}, status_code=404)
    return Response(content=tracker_file.read_text(encoding="utf-8"), media_type="application/json")


SPA_DIR = Path("/home/aiagent/wazuh-soc/dist")
if SPA_DIR.exists():
    app.mount("/wazuh-soc-v2/assets", StaticFiles(directory=str(SPA_DIR / "assets")), name="wazuh_soc_assets")

    @app.get("/wazuh-soc-v2", response_class=HTMLResponse)
    @app.get("/wazuh-soc-v2/", response_class=HTMLResponse)
    @app.get("/wazuh-soc-v2.html", response_class=HTMLResponse)
    def wazuh_soc_v2_index():
        return HTMLResponse(content=(SPA_DIR / "index.html").read_text(encoding="utf-8"))

