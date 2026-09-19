"""Platform core — organizations, RBAC, webhooks, onboarding."""
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("platform")

DATA_DIR = Path(__file__).parent
ORGS_FILE = DATA_DIR / "platform_orgs.json"
USERS_FILE = DATA_DIR / "platform_users.json"
WEBHOOKS_FILE = DATA_DIR / "platform_webhooks.json"
TOKENS_FILE = DATA_DIR / "platform_tokens.json"

# ── Default Org ─────────────────────────────────────────────────────────────
DEFAULT_ORG = {
    "id": "default",
    "name": "Default Organization",
    "slug": "default",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "settings": {
        "retention_days": 90,
        "max_agents": 100,
        "features": {"edr": True, "itdr": True, "siem": True, "reports": True},
    },
}

# ── Roles ───────────────────────────────────────────────────────────────────
ROLES = {
    "soc_admin": {
        "name": "SOC Admin",
        "permissions": [
            "org.read", "org.write", "org.delete",
            "users.read", "users.write", "users.delete",
            "alerts.read", "alerts.write", "alerts.respond",
            "edr.read", "edr.write", "edr.isolate", "edr.kill",
            "itdr.read", "itdr.write",
            "siem.read", "siem.ingest",
            "reports.read", "reports.generate",
            "webhooks.read", "webhooks.write", "webhooks.delete",
            "settings.read", "settings.write",
        ],
    },
    "soc_analyst": {
        "name": "SOC Analyst",
        "permissions": [
            "org.read",
            "alerts.read", "alerts.write", "alerts.respond",
            "edr.read", "edr.write", "edr.isolate", "edr.kill",
            "itdr.read",
            "siem.read",
            "reports.read",
        ],
    },
    "soc_viewer": {
        "name": "SOC Viewer",
        "permissions": [
            "org.read",
            "alerts.read",
            "edr.read",
            "itdr.read",
            "siem.read",
            "reports.read",
        ],
    },
    "client_admin": {
        "name": "Client Admin",
        "permissions": [
            "org.read",
            "alerts.read", "alerts.write",
            "edr.read",
            "itdr.read",
            "siem.read",
            "reports.read",
        ],
    },
    "client_viewer": {
        "name": "Client Viewer",
        "permissions": [
            "alerts.read",
            "edr.read",
            "reports.read",
        ],
    },
}


# ═══════════════════════════════════════════════════════
#  Storage helpers
# ═══════════════════════════════════════════════════════

def _load_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default or []


def _save_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ═══════════════════════════════════════════════════════
#  Organizations
# ═══════════════════════════════════════════════════════

def get_orgs() -> list[dict]:
    orgs = _load_json(ORGS_FILE, [])
    if not orgs:
        orgs = [DEFAULT_ORG]
        _save_json(ORGS_FILE, orgs)
    return orgs


def create_org(name: str, slug: str = "") -> dict:
    orgs = get_orgs()
    if not slug:
        slug = name.lower().replace(" ", "-") + "-" + secrets.token_hex(4)
    org = {
        "id": slug,
        "name": name,
        "slug": slug,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "settings": {"retention_days": 90, "max_agents": 100, "features": {"edr": True, "itdr": True, "siem": True}},
    }
    orgs.append(org)
    _save_json(ORGS_FILE, orgs)
    return org


def delete_org(org_id: str) -> bool:
    orgs = get_orgs()
    filtered = [o for o in orgs if o["id"] != org_id and o["id"] != "default"]
    if len(filtered) == len(orgs):
        return False
    _save_json(ORGS_FILE, filtered)
    return True


# ═══════════════════════════════════════════════════════
#  Users
# ═══════════════════════════════════════════════════════

def get_users() -> list[dict]:
    return _load_json(USERS_FILE, [])


def add_user(username: str, role: str, org_id: str = "default") -> dict:
    users = get_users()
    user = {
        "id": secrets.token_hex(8),
        "username": username,
        "role": role if role in ROLES else "soc_viewer",
        "org_id": org_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    users.append(user)
    _save_json(USERS_FILE, users)
    return user


def update_user_role(user_id: str, role: str) -> bool:
    users = get_users()
    for u in users:
        if u["id"] == user_id:
            u["role"] = role if role in ROLES else u["role"]
            _save_json(USERS_FILE, users)
            return True
    return False


def check_permission(user_role: str, permission: str) -> bool:
    role_def = ROLES.get(user_role)
    if not role_def:
        return False
    return permission in role_def["permissions"]


# ═══════════════════════════════════════════════════════
#  Webhooks
# ═══════════════════════════════════════════════════════

def get_webhooks() -> list[dict]:
    return _load_json(WEBHOOKS_FILE, [])


def register_webhook(url: str, events: list[str], org_id: str = "default") -> dict:
    whs = get_webhooks()
    wh = {
        "id": secrets.token_hex(8),
        "url": url,
        "events": events,
        "org_id": org_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    whs.append(wh)
    _save_json(WEBHOOKS_FILE, whs)
    return wh


def delete_webhook(wh_id: str) -> bool:
    whs = get_webhooks()
    filtered = [w for w in whs if w["id"] != wh_id]
    if len(filtered) == len(whs):
        return False
    _save_json(WEBHOOKS_FILE, filtered)
    return True


def dispatch_webhooks(event_type: str, payload: dict):
    """Fire webhooks for a given event type."""
    import requests as req
    whs = get_webhooks()
    for wh in whs:
        if not wh.get("active"):
            continue
        if event_type in wh.get("events", []):
            try:
                req.post(wh["url"], json={"event": event_type, "payload": payload}, timeout=10)
            except Exception as e:
                logger.warning("Webhook %s failed: %s", wh["url"], e)


# ═══════════════════════════════════════════════════════
#  Deploy Tokens
# ═══════════════════════════════════════════════════════

def get_tokens() -> list[dict]:
    return _load_json(TOKENS_FILE, [])


def create_token(org_id: str = "default", label: str = "") -> dict:
    tokens = get_tokens()
    token = {
        "id": secrets.token_hex(12),
        "token": "soc_" + secrets.token_hex(24),
        "org_id": org_id,
        "label": label or f"Token-{len(tokens)+1}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    tokens.append(token)
    _save_json(TOKENS_FILE, tokens)
    return token


def revoke_token(token_id: str) -> bool:
    tokens = get_tokens()
    for t in tokens:
        if t["id"] == token_id:
            t["active"] = False
            _save_json(TOKENS_FILE, tokens)
            return True
    return False


def validate_token(token_str: str) -> dict | None:
    tokens = get_tokens()
    for t in tokens:
        if t.get("token") == token_str and t.get("active", False):
            return t
    return None


# ═══════════════════════════════════════════════════════
#  Onboarding
# ═══════════════════════════════════════════════════════

