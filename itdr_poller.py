"""ITDR — Identity Threat Detection & Response (multi-tenant).

Polls Microsoft Graph API for identity signals across every managed M365
tenant: sign-in logs, directory audit logs, Entra ID risk detections, risky
users. Runs ITDR detection rules over new events, creates cases for confirmed
detections, and keeps a per-tenant poll status.

Architecture:
    start_poller() ─► poll_all_tenants() ─► poll_tenant(t) ─► fetch_* (Graph)
                       │                        │
                       │                        ├─► store_events (itdr_events.json)
                       │                        └─► run_detections ─► save_case
                       └─► /api/itdr/* endpoints (soc_api.py)

Tenant registry: itdr_tenants.json — metadata only (id, name, tenant_id,
org_id, enabled, last_poll). Secrets stay in .env:

    ITDR_SIMPLYICT_TENANT_ID      (optional; registry value is authoritative)
    ITDR_SIMPLYICT_CLIENT_ID
    ITDR_SIMPLYICT_CLIENT_SECRET

The legacy single-tenant vars (ITDR_TENANT_ID / ITDR_CLIENT_ID /
ITDR_CLIENT_SECRET) are honoured as the reserved tenant id "default", so
existing deployments keep working unchanged.

Setup per tenant:
    1. Azure AD app registration with API permissions:
       - AuditLog.Read.All, IdentityRiskEvent.Read.All
       - Directory.Read.All, MailboxSettings.Read
    2. Grant admin consent; store client id/secret in .env (see above).
"""
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from itdr_detections import SOC_DONE_STATES, is_soc_actioned, run_detections

logger = logging.getLogger("itdr")

# ── Config ──────────────────────────────────────────────────────────────────
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ITDR_STORE = Path(__file__).parent / "itdr_events.json"
ITDR_CASES = Path(__file__).parent / "itdr_cases.json"
TENANTS_FILE = Path(__file__).parent / "itdr_tenants.json"
STATUS_FILE = Path(__file__).parent / "itdr_poll_status.json"
CREDS_FILE = Path(__file__).parent / "itdr_tenant_creds.json"  # mode 600; written by onboarding
POLL_INTERVAL_MIN = float(os.getenv("ITDR_POLL_INTERVAL_MIN", "5"))
MAX_EVENTS = 5000
MAX_CASES = 500

# Legacy single-tenant credentials — resolve as tenant id "default".
LEGACY_CREDS = {
    "tenant_id": os.getenv("ITDR_TENANT_ID", "").strip(),
    "client_id": os.getenv("ITDR_CLIENT_ID", "").strip(),
    "client_secret": os.getenv("ITDR_CLIENT_SECRET", "").strip(),
}

# Per-tenant in-memory token cache: tenant_id -> {"value", "expires_at"}
_token_cache: dict[str, dict] = {}
_poller_thread: threading.Thread | None = None
_poller_lock = threading.Lock()


# ═══════════════════════════════════════════════════════
#  Tenant Registry
# ═══════════════════════════════════════════════════════

def _load_tenants() -> list[dict]:
    try:
        if TENANTS_FILE.exists():
            data = json.loads(TENANTS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data.get("tenants", [])
            if isinstance(data, list):
                return data
    except Exception as e:
        logger.warning("Failed to load tenant registry: %s", e)
    return []


def _save_tenants(tenants: list[dict]):
    try:
        TENANTS_FILE.write_text(
            json.dumps({"tenants": tenants}, indent=2, default=str), encoding="utf-8"
        )
    except Exception as e:
        logger.warning("Failed to save tenant registry: %s", e)


def _legacy_default_tenant() -> dict | None:
    """Synthesise the legacy env-var tenant when nothing is registered yet."""
    if not any(LEGACY_CREDS.values()):
        return None
    return {
        "id": "default",
        "name": "Default (legacy env)",
        "tenant_id": LEGACY_CREDS.get("tenant_id", ""),
        "org_id": "default",
        "enabled": True,
        "env_prefix": "",
        "last_poll": None,
        "last_status": None,
        "last_error": None,
        "event_count": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _load_status() -> dict:
    try:
        return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_status(status: dict) -> None:
    try:
        STATUS_FILE.write_text(json.dumps(status, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        logger.warning("could not persist poll status: %s", e)


def get_tenants() -> list[dict]:
    """Every tenant with its last poll status merged in.

    Poll results live in itdr_poll_status.json (runtime state) while the registry
    holds configuration — and the legacy env tenant has no registry row at all,
    so its status would otherwise be invisible.
    """
    tenants = _load_tenants()
    if not tenants:
        legacy = _legacy_default_tenant()
        if legacy:
            tenants = [legacy]
    status = _load_status()
    for t in tenants:
        st = status.get(t.get("id", "")) or {}
        for k in ("last_poll", "last_status", "last_error", "last_counts", "defender"):
            if k in st:
                t[k] = st[k]
    return tenants


def get_tenant(tenant_id: str) -> dict | None:
    for t in get_tenants():
        if t.get("id") == tenant_id:
            return t
    return None


def create_tenant(name: str, tenant_id: str = "", org_id: str = "default",
                  env_prefix: str = "") -> dict:
    """Register a tenant. id is derived from env_prefix/name; secrets go to .env."""
    if not name.strip():
        raise ValueError("name is required")
    tenants = _load_tenants()
    raw_id = (env_prefix or name).strip().lower()
    tid = "".join(c if c.isalnum() else "_" for c in raw_id).strip("_") or "tenant"
    if tid == "default":
        tid = "tenant_" + uuid.uuid4().hex[:6]
    if any(t.get("id") == tid for t in tenants):
        raise ValueError(f"tenant id '{tid}' already exists")
    tenant = {
        "id": tid,
        "name": name.strip(),
        "tenant_id": (tenant_id or "").strip(),
        "org_id": org_id or "default",
        "enabled": True,
        "env_prefix": (env_prefix or tid).strip().upper(),
        "last_poll": None,
        "last_status": None,
        "last_error": None,
        "event_count": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    tenants.insert(0, tenant)
    _save_tenants(tenants)
    return tenant


def update_tenant(tenant_id: str, fields: dict) -> dict | None:
    """Update non-secret fields (enabled, name, tenant_id, org_id). Returns updated tenant."""
    tenants = _load_tenants()
    for t in tenants:
        if t.get("id") == tenant_id:
            for k in ("enabled", "name", "tenant_id", "org_id"):
                if k in fields and fields[k] is not None:
                    t[k] = fields[k]
            _save_tenants(tenants)
            return t
    return None


def delete_tenant(tenant_id: str) -> bool:
    if tenant_id == "default":
        return False  # legacy env tenant cannot be deleted via registry
    tenants = [t for t in _load_tenants() if t.get("id") != tenant_id]
    _save_tenants(tenants)
    _token_cache.pop(tenant_id, None)
    return True


def load_credentials() -> dict:
    """Per-tenant secrets captured through onboarding (file mode 600)."""
    try:
        return json.loads(CREDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_credentials(tenant_id: str, creds: dict) -> None:
    all_creds = load_credentials()
    entry = all_creds.get(tenant_id) or {}
    for k in ("tenant_id", "client_id", "client_secret"):
        if creds.get(k):
            entry[k] = str(creds[k]).strip()
    all_creds[tenant_id] = entry
    CREDS_FILE.write_text(json.dumps(all_creds, indent=2), encoding="utf-8")
    try:
        os.chmod(CREDS_FILE, 0o600)
    except OSError:
        pass
    _token_cache.pop(tenant_id, None)
    _DEFENDER_PROBE.pop(tenant_id, None)


def has_credentials(tenant_id: str) -> bool:
    c = load_credentials().get(tenant_id) or {}
    return bool(c.get("client_id") and c.get("client_secret"))


def _tenant_credentials(tenant: dict) -> dict:
    """Resolve client id/secret/tenant id for a tenant.

    Order: onboarding file (UI) → env vars for the tenant's prefix → legacy env.
    """
    if not tenant:
        return {}
    tid = tenant.get("id", "")
    if tid == "default":
        stored = load_credentials().get("default") or {}
        return {k: stored.get(k) or LEGACY_CREDS.get(k, "") for k in
                ("tenant_id", "client_id", "client_secret")}
    prefix = (tenant.get("env_prefix") or tid).upper()
    stored = load_credentials().get(tid) or {}
    creds = {
        "tenant_id": (os.getenv(f"ITDR_{prefix}_TENANT_ID", "").strip()
                      or stored.get("tenant_id") or (tenant.get("tenant_id") or "").strip()),
        "client_id": os.getenv(f"ITDR_{prefix}_CLIENT_ID", "").strip() or stored.get("client_id", ""),
        "client_secret": (os.getenv(f"ITDR_{prefix}_CLIENT_SECRET", "").strip()
                          or stored.get("client_secret", "")),
    }
    return creds


def is_configured(tenant: dict) -> bool:
    creds = _tenant_credentials(tenant)
    return all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")])


# ═══════════════════════════════════════════════════════
#  Auth (per-tenant token cache)
# ═══════════════════════════════════════════════════════

def get_token(tenant: dict | None = None, force: bool = False) -> str:
    """Get Microsoft Graph access token via client credentials flow (per tenant)."""
    if tenant is None:
        tenant = _legacy_default_tenant()
    if not tenant:
        return ""
    tid = tenant.get("id", "")
    cached = _token_cache.get(tid)
    if not force and cached and cached.get("value") and time.time() < cached.get("expires_at", 0) - 60:
        return cached["value"]

    creds = _tenant_credentials(tenant)
    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return ""

    url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
    try:
        r = requests.post(url, data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "https://graph.microsoft.com/.default",
        }, timeout=30)
        r.raise_for_status()
        data = r.json()
        _token_cache[tid] = {"value": data["access_token"], "expires_at": time.time() + data.get("expires_in", 3600)}
        return data["access_token"]
    except Exception as e:
        logger.error("Failed to get Graph token for tenant '%s': %s", tid, e)
        return ""


def _headers(tenant: dict | None = None) -> dict:
    tok = get_token(tenant)
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"} if tok else {}


# ═══════════════════════════════════════════════════════
#  Data Sources (all take tenant)
# ═══════════════════════════════════════════════════════

def fetch_sign_ins(tenant: dict, since: str | None = None, limit: int = 500) -> list[dict]:
    """Fetch sign-in logs from Entra ID."""
    url = f"{GRAPH_BASE}/auditLogs/signIns?$top={limit}&$orderby=createdDateTime desc"
    if since:
        url += f"&$filter=createdDateTime ge {since}"
    try:
        r = requests.get(url, headers=_headers(tenant), timeout=30)
        r.raise_for_status()
        return r.json().get("value", [])
    except Exception as e:
        logger.warning("Failed to fetch sign-ins (tenant %s): %s", tenant.get("id"), e)
        return []


def fetch_audit_logs(tenant: dict, since: str | None = None, limit: int = 500) -> list[dict]:
    """Fetch directory audit logs."""
    url = f"{GRAPH_BASE}/auditLogs/directoryAudits?$top={limit}&$orderby=activityDateTime desc"
    if since:
        url += f"&$filter=activityDateTime ge {since}"
    try:
        r = requests.get(url, headers=_headers(tenant), timeout=30)
        r.raise_for_status()
        return r.json().get("value", [])
    except Exception as e:
        logger.warning("Failed to fetch audit logs (tenant %s): %s", tenant.get("id"), e)
        return []


def fetch_risk_detections(tenant: dict, since: str | None = None, limit: int = 200) -> list[dict]:
    """Fetch Entra ID Identity Protection risk detections."""
    url = f"{GRAPH_BASE}/identityProtection/riskDetections?$top={limit}&$orderby=detectedDateTime desc"
    if since:
        url += f"&$filter=detectedDateTime ge {since}"
    try:
        r = requests.get(url, headers=_headers(tenant), timeout=30)
        r.raise_for_status()
        return r.json().get("value", [])
    except Exception as e:
        logger.warning("Failed to fetch risk detections (tenant %s): %s", tenant.get("id"), e)
        return []


def fetch_risky_users(tenant: dict) -> list[dict]:
    """Fetch users flagged as risky by Entra ID."""
    url = f"{GRAPH_BASE}/identityProtection/riskyUsers?$top=100"
    try:
        r = requests.get(url, headers=_headers(tenant), timeout=30)
        r.raise_for_status()
        return r.json().get("value", [])
    except Exception as e:
        logger.warning("Failed to fetch risky users (tenant %s): %s", tenant.get("id"), e)
        return []


# ═══════════════════════════════════════════════════════
#  Event Store
# ═══════════════════════════════════════════════════════

def _load_events() -> list[dict]:
    try:
        if ITDR_STORE.exists():
            return json.loads(ITDR_STORE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_events(events: list[dict]):
    try:
        ITDR_STORE.write_text(json.dumps(events, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save ITDR events: %s", e)


def mark_event_decision(event_id: str, status: str = "", note: str = "",
                        analyst: str = "soc") -> dict | None:
    """Record an analyst decision on the event itself.

    Every resolution entry point (M365 Defender panel, ITDR cases tab, review
    queue) goes through here: `soc_status` is what makes run_detections() skip the
    event, so a decision taken in any one view stops the case being re-raised.
    `status="open"` clears the decision (reopen).
    """
    events = _load_events()
    hit = None
    for e in events:
        if e.get("id") != event_id:
            continue
        now = datetime.now(timezone.utc)
        if status:                      # "" = note only, leave the decision alone
            if status == "open":
                e["soc_status"] = ""
                e["actioned_at"] = ""
            else:
                e["soc_status"] = status
                e["actioned_at"] = now.isoformat()
            e["status"] = status
        e["updated_at"] = now.isoformat()
        if note:
            e["notes"] = (e.get("notes") or "") + f"\n[{now:%Y-%m-%d %H:%M} {analyst}] {note[:500]}"
        hit = e
        break
    if hit is not None:
        _save_events(events)
    return hit


def store_events(new_events: list[dict], tenant: dict | None = None):
    """Merge new events into the store (dedup by id), tagged with tenant."""
    existing = _load_events()
    existing_ids = {e.get("id", "") for e in existing}
    merged = existing[:]
    for ev in new_events:
        eid = ev.get("id", "")
        if eid and eid not in existing_ids:
            if tenant:
                ev.setdefault("tenant_id", tenant.get("id", ""))
                ev.setdefault("tenant_name", tenant.get("name", ""))
            merged.insert(0, ev)
            existing_ids.add(eid)
    if len(merged) > MAX_EVENTS:
        merged = merged[:MAX_EVENTS]
    _save_events(merged)


def get_events(filters: dict | None = None, limit: int = 200) -> list[dict]:
    """Get stored ITDR events with optional severity/source/detection_type/tenant_id filtering."""
    events = _load_events()
    if filters:
        for key, value in filters.items():
            if value and key in ("severity", "source", "detection_type", "tenant_id"):
                events = [e for e in events if e.get(key) == value]
    return events[:limit]


# ═══════════════════════════════════════════════════════
#  Cases
# ═══════════════════════════════════════════════════════

def update_case(case_id: str, updates: dict) -> dict | None:
    """Patch a case in place (status, notes, assignee, ...). Returns the case."""
    if not ITDR_CASES.exists():
        return None
    try:
        cases = json.loads(ITDR_CASES.read_text(encoding="utf-8"))
    except Exception:
        return None
    updated = None
    for c in cases:
        if c.get("id") == case_id:
            c.update(updates)
            updated = c
            break
    if updated is not None:
        ITDR_CASES.write_text(json.dumps(cases, indent=2, default=str), encoding="utf-8")
    return updated


def get_cases(tenant_id: str | None = None) -> list[dict]:
    try:
        if ITDR_CASES.exists():
            cases = json.loads(ITDR_CASES.read_text(encoding="utf-8"))
            if tenant_id:
                cases = [c for c in cases if c.get("tenant_id") == tenant_id]
            return cases
    except Exception:
        pass
    return []


def save_case(case: dict):
    cases = get_cases()
    cases.insert(0, case)
    if len(cases) > MAX_CASES:
        cases = cases[:MAX_CASES]
    ITDR_CASES.write_text(json.dumps(cases, indent=2, default=str), encoding="utf-8")


# ═══════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════

def get_summary() -> dict:
    """Get ITDR dashboard summary (all tenants, with per-tenant breakdown)."""
    events = _load_events()
    cases = get_cases()
    total = len(events)
    critical = sum(1 for e in events if e.get("severity") == "critical")
    high = sum(1 for e in events if e.get("severity") == "high")
    medium = sum(1 for e in events if e.get("severity") == "medium")
    by_source = {}
    by_tenant = {}
    for e in events:
        src = e.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        tid = e.get("tenant_id") or "default"
        bucket = by_tenant.setdefault(tid, {"name": e.get("tenant_name", tid), "events": 0})
        bucket["events"] += 1

    tenants_out = []
    configured = 0
    for t in get_tenants():
        tid = t.get("id", "")
        t_events = by_tenant.get(tid, {}).get("events", 0)
        t_cases = sum(1 for c in cases if c.get("tenant_id") == tid)
        ready = is_configured(t)
        if ready and t.get("enabled", True):
            configured += 1
        perms = {}
        try:
            perms = graph_permissions(t)          # cached probe (1 h TTL)
        except Exception:
            perms = {}
        tenants_out.append({
            "id": tid,
            "name": t.get("name", tid),
            "tenant_id": t.get("tenant_id", ""),
            "org_id": t.get("org_id", "default"),
            "identity": perms.get("identity", ""),
            "defender": perms.get("defender", ""),
            "defender_missing_roles": perms.get("defender_missing_roles", []),
            "mde": t.get("mde") or "",
            "mde_missing_roles": (mde_permissions(t).get("missing_roles") or []),
            "last_counts": t.get("last_counts") or {},
            "enabled": t.get("enabled", True),
            "configured": ready,
            "last_poll": t.get("last_poll"),
            "last_status": t.get("last_status"),
            "last_error": t.get("last_error"),
            "event_count": t_events,
            "case_count": t_cases,
        })

    return {
        "total_events": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": total - critical - high - medium,
        "open_cases": sum(1 for c in cases if c.get("status") in ("open", "investigating")),
        "by_source": by_source,
        "by_tenant": by_tenant,
        "tenants": tenants_out,
        "sources_configured": configured > 0,
    }


# ═══════════════════════════════════════════════════════
#  Poll Cycle
# ═══════════════════════════════════════════════════════

def _graph_ts(value) -> str:
    """ISO-8601 the Graph API accepts: second precision, Z suffix, no offset."""
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _last_event_ts(tenant_id: str) -> str | None:
    """Newest stored event timestamp for a tenant (Graph filter window base)."""
    for e in _load_events():
        if (e.get("tenant_id") or "default") == tenant_id:
            ts = e.get("created_at") or e.get("detected_at") or ""
            if ts:
                return ts
    return None


def _mark_poll(tenant_id: str, status: str, error: str | None = None,
               counts: dict | None = None, defender: str | None = None):
    """Record a poll result (runtime state; survives the legacy env tenant too)."""
    all_status = _load_status()
    entry = all_status.get(tenant_id) or {}
    entry.update({"last_poll": _now_iso(), "last_status": status, "last_error": error})
    if counts is not None:
        entry["last_counts"] = counts
    if defender is not None:
        entry["defender"] = defender
    all_status[tenant_id] = entry
    _save_status(all_status)
    """Persist poll status onto the tenant registry row."""
    tenants = _load_tenants()
    changed = False
    for t in tenants:
        if t.get("id") == tenant_id:
            t["last_poll"] = datetime.now(timezone.utc).isoformat()
            t["last_status"] = status
            t["last_error"] = error
            changed = True
            break
    if changed:
        _save_tenants(tenants)


# ── Microsoft Defender (M365 security) ────────────────────────────────────
# The same app registration must be granted the Defender XDR application roles;
# without them Graph answers 403 "Missing application roles", which we surface as
# a per-tenant status instead of failing the poll.

DEFENDER_ROLES = ("SecurityAlert.Read.All", "SecurityIncident.Read.All")

# tenant id -> (checked_at, status dict)
_DEFENDER_PROBE: dict[str, tuple[float, dict]] = {}
_PROBE_TTL = 3600


def graph_permissions(tenant: dict, force: bool = False) -> dict:
    """Which Graph capabilities this tenant's app can actually use.

    Probes one cheap request per area and reports the outcome, so onboarding can
    tell the admin exactly what to grant/consent.
    """
    tid = tenant.get("id", "default")
    cached = _DEFENDER_PROBE.get(tid)
    if cached and not force and time.time() - cached[0] < _PROBE_TTL:
        return cached[1]
    out = {"identity": "", "defender": "", "defender_missing_roles": [], "checked_at": _now_iso()}
    headers = _headers(tenant)
    if not headers.get("Authorization"):
        out.update({"identity": "no_credentials", "defender": "no_credentials"})
        _DEFENDER_PROBE[tid] = (time.time(), out)
        return out
    probes = (
        ("identity", f"{GRAPH_BASE}/auditLogs/signIns?$top=1"),
        ("defender", f"{GRAPH_BASE}/security/alerts_v2?$top=1"),
    )
    for area, url in probes:
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 200:
                out[area] = "ok"
            elif r.status_code == 403:
                body = r.text[:600]
                roles = [x for x in DEFENDER_ROLES if x in body]
                if not roles:
                    roles = [x.strip() for x in body.split("API required roles:")[-1].split(",")][:4]
                out[area] = "missing_roles"
                if area == "defender":
                    out["defender_missing_roles"] = [x for x in roles if x]
            else:
                out[area] = f"http_{r.status_code}"
        except Exception as e:
            out[area] = f"error: {str(e)[:60]}"
    # Re-check soon while something is missing (an admin usually grants within
    # minutes); cache longer once everything is granted.
    ttl = _PROBE_TTL if out.get("identity") == "ok" and out.get("defender") == "ok" else 300
    _DEFENDER_PROBE[tid] = (time.time() - _PROBE_TTL + ttl, out)
    return out


# ── Microsoft Defender for Endpoint (device alerts) ───────────────────────
# A separate API (api.security.microsoft.com) and its own app roles
# (Alert.Read.All for alerts, Machine.Read.All for device inventory) — granted on
# the same app registration, but under the "Microsoft Defender for Endpoint"
# resource, not Microsoft Graph.

MDE_BASE = "https://api.security.microsoft.com"
MDE_SCOPE = "https://api.security.microsoft.com/.default"
MDE_ROLES = ("Alert.Read.All", "Machine.Read.All")

_mde_token_cache: dict[str, dict] = {}
_MDE_PROBE: dict[str, tuple[float, dict]] = {}


def mde_token(tenant: dict, force: bool = False) -> str:
    creds = _tenant_credentials(tenant)
    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return ""
    tid = tenant.get("id", "")
    cached = _mde_token_cache.get(tid)
    if not force and cached and cached.get("value") and time.time() < cached.get("expires_at", 0) - 60:
        return cached["value"]
    try:
        r = requests.post(f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token",
                          data={"grant_type": "client_credentials", "client_id": creds["client_id"],
                                "client_secret": creds["client_secret"], "scope": MDE_SCOPE}, timeout=30)
        r.raise_for_status()
        body = r.json()
        _mde_token_cache[tid] = {"value": body.get("access_token", ""),
                                 "expires_at": time.time() + int(body.get("expires_in", 3600))}
        return _mde_token_cache[tid]["value"]
    except Exception as e:
        logger.warning("MDE token failed (tenant %s): %s", tid, str(e)[:100])
        return ""


def mde_headers(tenant: dict) -> dict:
    tok = mde_token(tenant)
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def mde_permissions(tenant: dict, force: bool = False) -> dict:
    """Whether Defender for Endpoint alerts reach us — via Graph (preferred) or the legacy MDE API.

    Graph's security/alerts_v2 already returns Defender-for-Endpoint alerts
    (serviceSource microsoftDefenderForEndpoint) under SecurityAlert.Read.All, so
    the WindowsDefenderATP roles are only needed for the legacy api.security.microsoft.com
    feed; missing them is not a defect.
    """
    tid = tenant.get("id", "default")
    cached = _MDE_PROBE.get(tid)
    if cached and not force and time.time() - cached[0] < 300:
        return cached[1]
    out = {"status": "", "missing_roles": [], "checked_at": _now_iso()}
    graph_read = "SecurityAlert.Read.All" in _jwt_roles(get_token(tenant))
    legacy_roles = _jwt_roles(mde_token(tenant))
    if graph_read and "Alert.Read.All" not in legacy_roles:
        out["status"] = "ok"
        out["via"] = "graph"
        out["note"] = "endpoint alerts arrive via Graph alerts_v2"
        _MDE_PROBE[tid] = (time.time(), out)
        return out
    headers = mde_headers(tenant)
    if not headers:
        out["status"] = "no_credentials"
    else:
        try:
            r = requests.get(f"{MDE_BASE}/api/alerts?$top=1", headers=headers, timeout=30)
            if r.status_code == 200:
                out["status"] = "ok"
                out["via"] = "legacy-mde"
            elif r.status_code == 403:
                body = r.text[:600]
                out["status"] = "missing_roles"
                roles = [x for x in MDE_ROLES if x in body]
                out["missing_roles"] = roles or [x.strip() for x in
                                                 body.split("API required roles:")[-1].split(",")][:3]
            elif r.status_code == 401:
                out["status"] = "unauthorized"
            else:
                out["status"] = f"http_{r.status_code}"
        except Exception as e:
            out["status"] = f"error: {str(e)[:60]}"
    _MDE_PROBE[tid] = (time.time(), out)
    return out


def _jwt_roles(token: str) -> set:
    """Roles granted to the app, read straight from its token (no guessing)."""
    try:
        import base64
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return set(json.loads(base64.urlsafe_b64decode(payload)).get("roles") or [])
    except Exception:
        return set()


_WRITE_ROLES = ("SecurityAlert.ReadWrite.All", "SecurityIncident.ReadWrite.All",
                "Alert.ReadWrite.All")


def write_capabilities(tenant: dict) -> dict:
    """Which Defender write-back paths this tenant's app can use.

    A token minted before an admin consented to a new role keeps its old claims
    for up to an hour, so re-mint once when the cached token lacks write roles —
    otherwise a fresh grant looks un-applied until the cache expires.
    """
    graph_roles = _jwt_roles(get_token(tenant))
    if not graph_roles.intersection(_WRITE_ROLES):
        graph_roles = _jwt_roles(get_token(tenant, force=True))
    mde_roles = _jwt_roles(mde_token(tenant))
    if "Alert.ReadWrite.All" not in mde_roles:
        mde_roles = _jwt_roles(mde_token(tenant, force=True))
    graph_alert_write = "SecurityAlert.ReadWrite.All" in graph_roles
    legacy_mde_write = "Alert.ReadWrite.All" in mde_roles
    return {
        "xdr_alerts": graph_alert_write,
        "xdr_incidents": "SecurityIncident.ReadWrite.All" in graph_roles,
        # Graph alerts_v2 covers Defender-for-Endpoint alerts, so the Graph role alone
        # is enough — the legacy WindowsDefenderATP role is only an alternative.
        "endpoint_alerts": graph_alert_write or legacy_mde_write,
        "endpoint_via": "graph" if graph_alert_write else ("legacy-mde" if legacy_mde_write else ""),
        "missing": [r for r, ok in (("SecurityAlert.ReadWrite.All", graph_alert_write),
                                    ("SecurityIncident.ReadWrite.All", "SecurityIncident.ReadWrite.All" in graph_roles))
                    if not ok],
        "missing_optional": [] if (graph_alert_write or legacy_mde_write) else [
            "Alert.ReadWrite.All (WindowsDefenderATP, only for the legacy MDE API)"],
    }


# Defender status/classification vocabulary, per API.
_XDR_STATUS = {"resolve": "resolved", "dismiss": "resolved", "reopen": "inProgress"}
_XDR_CLASSIFICATION = {"resolve": "truePositive", "dismiss": "falsePositive"}
_MDE_STATUS = {"resolve": "Resolved", "dismiss": "Resolved", "reopen": "InProgress"}
_MDE_CLASSIFICATION = {"resolve": "TruePositive", "dismiss": "FalsePositive",
                       "reopen": "Unknown"}


def push_defender_update(tenant: dict, source: str, item_id: str, action: str,
                         comment: str = "") -> dict:
    """Push a SOC decision back to Microsoft Defender (no-op without write roles).

    Returns {"pushed": bool, "detail": str} — never raises.
    """
    caps = write_capabilities(tenant)
    if action not in _XDR_STATUS:
        return {"pushed": False, "detail": f"no Defender mapping for action '{action}'"}
    try:
        if source == "defenderAlert":
            if not caps["xdr_alerts"]:
                return {"pushed": False, "detail": "needs SecurityAlert.ReadWrite.All"}
            r = requests.patch(f"{GRAPH_BASE}/security/alerts_v2/{item_id}",
                               headers=_headers(tenant),
                               json={"status": _XDR_STATUS[action],
                                     "classification": _XDR_CLASSIFICATION.get(action, "unknown"),
                                     "determination": "other" if action == "resolve" else "notAvailable",
                                     "comment": (comment or "")[:1000]}, timeout=30)
        elif source == "defenderIncident":
            if not caps["xdr_incidents"]:
                return {"pushed": False, "detail": "needs SecurityIncident.ReadWrite.All"}
            r = requests.patch(f"{GRAPH_BASE}/security/incidents/{item_id}",
                               headers=_headers(tenant),
                               json={"status": _XDR_STATUS[action],
                                     "classification": _XDR_CLASSIFICATION.get(action, "unknown"),
                                     "determination": "other" if action == "resolve" else "notAvailable",
                                     "customTags": [f"soc:{comment[:80]}"] if comment else []}, timeout=30)
        elif source == "mdeAlert":
            if caps["xdr_alerts"]:
                # Same Graph surface as XDR alerts (serviceSource microsoftDefenderForEndpoint)
                r = requests.patch(f"{GRAPH_BASE}/security/alerts_v2/{item_id}",
                                   headers=_headers(tenant),
                                   json={"status": _XDR_STATUS[action],
                                         "classification": _XDR_CLASSIFICATION.get(action, "unknown"),
                                         "determination": "other" if action == "resolve" else "notAvailable",
                                         "comment": (comment or "")[:1000]}, timeout=30)
            elif caps["endpoint_alerts"]:
                r = requests.patch(f"{MDE_BASE}/api/alerts/{item_id}",
                                   headers={**mde_headers(tenant), "Content-Type": "application/json"},
                                   json={"status": _MDE_STATUS[action],
                                         "classification": _MDE_CLASSIFICATION.get(action, "Unknown"),
                                         "determination": "Other",
                                         "comment": (comment or "")[:1000]}, timeout=30)
            else:
                return {"pushed": False, "detail": "needs SecurityAlert.ReadWrite.All"}
        else:
            return {"pushed": False, "detail": f"unknown source '{source}'"}
        if r.status_code in (200, 204):
            return {"pushed": True, "detail": f"{source} {action}: HTTP {r.status_code}"}
        return {"pushed": False, "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
    except Exception as e:
        return {"pushed": False, "detail": f"error: {str(e)[:120]}"}


def fetch_mde_alerts(tenant: dict, since: str | None = None, limit: int = 100) -> list[dict]:
    """Defender for Endpoint device alerts (api.security.microsoft.com/api/alerts)."""
    url = f"{MDE_BASE}/api/alerts?$top={limit}"
    if since:
        url += f"&$filter=alertCreationTime ge {_graph_ts(since)}"
    r = requests.get(url, headers=mde_headers(tenant), timeout=45)
    r.raise_for_status()
    return r.json().get("value", [])


_MDE_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "informational": "low"}
_MDE_STATUS = {"new": "new", "inprogress": "in_progress", "resolved": "resolved"}


def _mde_event(alert: dict, tenant: dict) -> dict:
    return {
        "id": alert.get("id", ""),
        "source": "mdeAlert",
        "created_at": alert.get("alertCreationTime") or alert.get("firstEventTime", ""),
        "user": alert.get("loggedOnUsers", [{}])[0].get("userName", "") if alert.get("loggedOnUsers") else "",
        "device": alert.get("computerDnsName") or alert.get("deviceName", ""),
        "device_id": alert.get("machineId", ""),
        "title": alert.get("title", ""),
        "severity": _MDE_SEVERITY.get(str(alert.get("severity", "")).lower(), "medium"),
        "status": _MDE_STATUS.get(str(alert.get("status", "")).lower().replace(" ", ""), "new"),
        "category": alert.get("category", ""),
        "service_source": "microsoftDefenderForEndpoint",
        "detection_source": alert.get("detectionSource", ""),
        "mitre": alert.get("mitreTechniques") or [],
        "description": alert.get("description", "") or alert.get("recommendedAction", ""),
        "incident_id": alert.get("incidentId", ""),
        "alert_web_url": alert.get("alertWebUrl", ""),
        "tenant_id": tenant.get("id", "default"),
        "tenant_name": tenant.get("name", ""),
    }


def fetch_defender_alerts(tenant: dict, since: str | None = None, limit: int = 200) -> list[dict]:
    """Defender XDR alerts (security/alerts_v2) — the threat feed for M365.

    No $expand/$select: alerts_v2 returns `evidence` by default, and asking for it
    explicitly fails ("Parsing OData Select and Expand failed" / 500).
    """
    url = f"{GRAPH_BASE}/security/alerts_v2?$top={limit}"
    if since:
        url += f"&$filter=createdDateTime ge {_graph_ts(since)}"
    r = requests.get(url, headers=_headers(tenant), timeout=45)
    r.raise_for_status()
    return r.json().get("value", [])


def fetch_defender_incidents(tenant: dict, since: str | None = None, limit: int = 50) -> list[dict]:
    """Defender XDR incidents (correlated alert groups).

    Incidents reject `ge` on createdDateTime and cap $top at 50 (both 400).
    """
    url = f"{GRAPH_BASE}/security/incidents?$top={min(limit, 50)}"
    if since:
        url += f"&$filter=createdDateTime gt {_graph_ts(since)}"
    r = requests.get(url, headers=_headers(tenant), timeout=45)
    r.raise_for_status()
    return r.json().get("value", [])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _defender_event(alert: dict, tenant: dict) -> dict:
    evidence = alert.get("evidence") or []
    user = ""
    device = ""
    for ev in evidence:
        if not user:
            user = (ev.get("userAccount", {}) or {}).get("accountName", "") or ev.get("userPrincipalName", "")
        if not device:
            device = ev.get("deviceName", "") or ev.get("hostName", "")
    return {
        "id": alert.get("id", ""),
        "source": "defenderAlert",
        "created_at": alert.get("createdDateTime", ""),
        "user": user,
        "device": device,
        "title": alert.get("title", ""),
        "severity": (alert.get("severity") or "unknown").lower(),
        "status": (alert.get("status") or "new").lower(),
        "category": alert.get("category", ""),
        "service_source": alert.get("serviceSource", ""),
        # Graph alerts_v2 already carries Defender-for-Endpoint alerts; tagging them
        # here means the Endpoint view needs no WindowsDefenderATP permission.
        "endpoint": alert.get("serviceSource", "") == "microsoftDefenderForEndpoint",
        "detection_source": alert.get("detectionSource", ""),
        "mitre": alert.get("mitreTechniques") or [],
        "description": alert.get("description", ""),
        "incident_id": alert.get("incidentId", ""),
        "tenant_id": tenant.get("id", "default"),
        "tenant_name": tenant.get("name", ""),
    }


def _defender_incident_event(inc: dict, tenant: dict) -> dict:
    return {
        "id": inc.get("id", ""),
        "source": "defenderIncident",
        "created_at": inc.get("createdDateTime", ""),
        "user": "",
        "device": "",
        "title": inc.get("displayName", "") or "Defender incident",
        "severity": (inc.get("severity") or "unknown").lower(),
        "status": (inc.get("status") or "active").lower(),
        "category": inc.get("classification", "") or "",
        "service_source": "defender_xdr",
        "alert_count": len(inc.get("alerts") or []),
        "description": ", ".join(sorted({(a.get("title") or "") for a in (inc.get("alerts") or [])}))[:400],
        "tenant_id": tenant.get("id", "default"),
        "tenant_name": tenant.get("name", ""),
    }


def poll_tenant(tenant_id: str) -> dict:
    """Run one full poll cycle for a single tenant: fetch → store → detect → case."""
    tenant = get_tenant(tenant_id)
    if tenant is None:
        return {"status": "error", "tenant_id": tenant_id, "message": "unknown tenant"}
    if not tenant.get("enabled", True):
        return {"status": "skipped", "tenant_id": tenant_id, "message": "tenant disabled"}
    if not is_configured(tenant):
        _mark_poll(tenant_id, "not_configured", "credentials missing in .env")
        return {"status": "not_configured", "tenant_id": tenant_id,
                "message": f"set ITDR_{tenant.get('env_prefix', tenant_id).upper()}_CLIENT_ID/_CLIENT_SECRET in .env"}
    if not get_token(tenant):
        _mark_poll(tenant_id, "auth_error", "token acquisition failed")
        return {"status": "error", "tenant_id": tenant_id, "message": "token acquisition failed"}

    # Polling window: last stored event for this tenant, else 24h ago. Graph wants
    # second precision with a Z suffix — datetime.isoformat() (+00:00, microseconds)
    # is rejected with HTTP 400, which used to break every poll of a fresh tenant.
    since = _graph_ts(_last_event_ts(tenant_id)) or _graph_ts(
        datetime.now(timezone.utc) - timedelta(hours=24))

    results = {"tenant_id": tenant_id, "sign_ins": 0, "audit_logs": 0,
               "risk_detections": 0, "defender_alerts": 0, "defender_incidents": 0,
               "mde_alerts": 0, "events_stored": 0, "detections": 0,
               "defender": None, "mde": None}
    new_events: list[dict] = []

    try:
        # Sign-ins
        for si in fetch_sign_ins(tenant, since):
            new_events.append({
                "id": si.get("id", ""),
                "source": "signIn",
                "created_at": si.get("createdDateTime", ""),
                "user": si.get("userPrincipalName", ""),
                "user_id": si.get("userId", ""),
                "app": si.get("appDisplayName", ""),
                "ip_address": si.get("ipAddress", ""),
                "location": si.get("location", {}).get("city", ""),
                "country": si.get("location", {}).get("countryOrRegion", ""),
                "status": si.get("status", {}).get("errorCode", 0),
                "status_detail": si.get("status", {}).get("failureReason", ""),
                "risk_level": si.get("riskLevelDuringSignIn", ""),
                "client_app": si.get("clientAppUsed", ""),
                "device": si.get("deviceDetail", {}).get("displayName", ""),
                "is_interactive": si.get("isInteractive", None),
                "mfa_required": si.get("authenticationMethodsUsed", []),
                "raw": si,
            })
        results["sign_ins"] = len(new_events)

        # Audit logs
        audit = []
        for al in fetch_audit_logs(tenant, since):
            audit.append({
                "id": al.get("id", ""),
                "source": "auditLog",
                "created_at": al.get("activityDateTime", ""),
                "user": ((al.get("initiatedBy", {}) or {}).get("user") or {}).get("userPrincipalName", ""),
                "activity": al.get("activityDisplayName", ""),
                "category": al.get("category", ""),
                "result": al.get("result", ""),
                "result_detail": al.get("resultReason", ""),
                "target_resources": [r.get("displayName", "") for r in (al.get("targetResources", []) or [])],
                "raw": al,
            })
        new_events.extend(audit)
        results["audit_logs"] = len(audit)

        # Risk detections
        risks = []
        for rd in fetch_risk_detections(tenant, since):
            risks.append({
                "id": rd.get("id", ""),
                "source": "riskDetection",
                "created_at": rd.get("detectedDateTime", rd.get("createdDateTime", "")),
                "user": rd.get("userPrincipalName", ""),
                "risk_type": rd.get("riskType", ""),
                "risk_level": rd.get("riskLevel", ""),
                "ip_address": rd.get("ipAddress", ""),
                "country": rd.get("location", {}).get("countryOrRegion", ""),
                "detail": rd.get("riskDetail", ""),
                "additional": rd.get("additionalInfo", ""),
                "raw": rd,
            })
        new_events.extend(risks)
        results["risk_detections"] = len(risks)

        # Microsoft Defender XDR (M365 threats) — only when the tenant's app has
        # the roles; otherwise record what to grant and keep polling identity.
        perms = graph_permissions(tenant)
        results["defender"] = perms.get("defender", "")
        if perms.get("defender") == "ok":
            try:
                alerts = fetch_defender_alerts(tenant, since)
                new_events.extend(_defender_event(a, tenant) for a in alerts)
                results["defender_alerts"] = len(alerts)
            except Exception as e:
                logger.warning("Defender alerts fetch failed (tenant %s): %s", tenant_id, str(e)[:120])
                results["defender"] = f"error: {str(e)[:80]}"
            try:
                incidents = fetch_defender_incidents(tenant, since)
                new_events.extend(_defender_incident_event(i, tenant) for i in incidents)
                results["defender_incidents"] = len(incidents)
            except Exception as e:
                logger.warning("Defender incidents fetch failed (tenant %s): %s", tenant_id, str(e)[:120])
        elif perms.get("defender") == "missing_roles":
            logger.warning("Defender roles not granted for tenant %s: %s",
                           tenant_id, perms.get("defender_missing_roles"))

        # Defender for Endpoint (device alerts). When Graph already delivers them
        # (serviceSource microsoftDefenderForEndpoint) the legacy MDE feed is skipped —
        # calling it without its roles only produces 403 noise.
        mde = mde_permissions(tenant)
        results["mde"] = mde.get("status", "")
        results["mde_via"] = mde.get("via", "")
        if mde.get("status") == "ok" and mde.get("via") == "legacy-mde":
            try:
                mde_alerts = fetch_mde_alerts(tenant, since)
                new_events.extend(_mde_event(a, tenant) for a in mde_alerts)
                results["mde_alerts"] = len(mde_alerts)
            except Exception as e:
                logger.warning("MDE alerts fetch failed (tenant %s): %s", tenant_id, str(e)[:120])
                results["mde"] = f"error: {str(e)[:80]}"
        elif mde.get("status") == "missing_roles":
            logger.warning("MDE roles not granted for tenant %s: %s", tenant_id, mde.get("missing_roles"))

        # Store tagged events
        store_events(new_events, tenant)
        results["events_stored"] = len(_load_events())

        # Run detections over this tenant's event window, create cases for hits.
        if new_events:
            tenant_events = [
                e for e in _load_events()
                if (e.get("tenant_id") or "default") == tenant_id
            ]
            detections = run_detections(tenant_events)
            results["detections"] = _create_cases_for_detections(detections, tenant)
    except Exception as e:
        logger.exception("ITDR poll failed for tenant '%s'", tenant_id)
        _mark_poll(tenant_id, "error", str(e))
        results["status"] = "error"
        results["message"] = str(e)
        return results

    _mark_poll(tenant_id, "ok", None, counts={
        k: results.get(k, 0) for k in ("sign_ins", "audit_logs", "risk_detections",
                                       "defender_alerts", "defender_incidents", "mde_alerts",
                                       "events_stored", "detections")},
        defender=results.get("defender") or "")
    results["status"] = "ok"
    return results


def _create_cases_for_detections(detections: list[dict], tenant: dict) -> int:
    """Persist new detections as open cases, deduped by key within 24h.

    A case already decided counts as a duplicate too (measured from when it was
    decided), so closing "Entra ID Risk — <user>" is not immediately followed by a
    fresh case for a sibling event of the same key. Cases use per-user keys for
    identity detections and per-event keys for Defender ones.
    """
    created = 0
    now = datetime.now(timezone.utc)
    existing = get_cases()
    for det in detections:
        user = det.get("user", "")
        dtype = det.get("detection_type", "")
        # Defender alerts/incidents dedupe on their own id (a device alert has no
        # user, so the identity key would collapse unrelated alerts together).
        by_event = det.get("dedup_field") == "event_id" and det.get("event_id")
        key = (tenant.get("id", ""), dtype, det.get("event_id", "") if by_event else user)
        dup = False
        for c in existing:
            cur = (c.get("tenant_id"), c.get("detection_type"),
                   c.get("event_id", "") if by_event else c.get("user"))
            decided = str(c.get("status") or "") in SOC_DONE_STATES
            if cur != key or not (decided or c.get("status") in ("open", "investigating")):
                continue
            # Decided cases age from when they were decided, open ones from creation.
            stamp = (c.get("updated_at") or c.get("created_at")) if decided else c.get("created_at")
            try:
                ts = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
                if now - ts <= timedelta(hours=24):
                    dup = True
                    break
            except Exception:
                dup = True  # unparseable ts → treat as recent to avoid spam
                break
        # High-impact Defender findings go to the human review queue as well, so
        # they show up on the dashboard/SLA board next to every other alert.
        if det.get("severity") in ("high", "critical") and dtype.startswith(("defender_", "mde_")):
            try:
                import soc_queue
                alert_id = det.get("event_id", "")
                already = any((q.get("details") or {}).get("alert_id") == alert_id
                              and q.get("source") == "m365-defender"
                              for q in soc_queue.get_queue())
                if not already:
                    soc_queue.create_item(
                        title=det.get("title", "Defender detection"),
                        severity=det.get("severity", "high"),
                        source="m365-defender",
                        details={"alert_id": alert_id, "tenant": tenant.get("id", ""),
                                 "tenant_name": tenant.get("name", ""), "user": user,
                                 "detection_type": dtype,
                                 "description": (det.get("description") or "")[:1000]})
            except Exception as e:
                logger.warning("queue hand-off failed: %s", str(e)[:120])


        if dup:
            continue

        case = {
            "id": "itdr-" + uuid.uuid4().hex[:12],
            "tenant_id": tenant.get("id", ""),
            "tenant_name": tenant.get("name", ""),
            "detection_type": dtype,
            "severity": det.get("severity", "high"),
            "title": det.get("title", "ITDR detection"),
            "description": det.get("description", ""),
            "user": user,
            "event_id": det.get("event_id", ""),
            "status": "open",
            "created_at": now.isoformat(),
        }
        save_case(case)
        existing.insert(0, case)
        created += 1
    return created


def poll_all_tenants() -> dict:
    """Poll every enabled tenant. Returns per-tenant results + totals."""
    per_tenant = []
    totals = {"sign_ins": 0, "audit_logs": 0, "risk_detections": 0, "events_stored": 0,
              "detections": 0, "tenants_polled": 0}
    for tenant in get_tenants():
        res = poll_tenant(tenant.get("id", ""))
        per_tenant.append(res)
        if res.get("status") == "ok":
            totals["tenants_polled"] += 1
            for k in ("sign_ins", "audit_logs", "risk_detections", "events_stored", "detections"):
                totals[k] += res.get(k, 0)
    totals["tenants"] = per_tenant
    totals["status"] = "ok"
    return totals


def poll_cycle() -> dict:
    """Backward-compatible alias: full poll across all tenants."""
    return poll_all_tenants()


# ═══════════════════════════════════════════════════════
#  Scheduler
# ═══════════════════════════════════════════════════════

def start_poller(interval_min: float | None = None) -> bool:
    """Start the background poller daemon (idempotent). Polls every interval_minutes.

    Multi-worker safe: each worker runs the loop, but the poll cycle itself is
    guarded by a file lock (LOCK_EX|LOCK_NB) so exactly one worker polls per
    interval — the others skip the cycle.
    """
    global _poller_thread
    interval = interval_min if interval_min is not None else POLL_INTERVAL_MIN
    with _poller_lock:
        if _poller_thread and _poller_thread.is_alive():
            return False

        def _loop():
            logger.info("ITDR poller started (interval=%.0fm)", interval)
            lock_path = Path(__file__).parent / "itdr_poller.lock"
            while True:
                try:
                    import fcntl
                    with open(lock_path, "w") as lf:
                        try:
                            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except OSError:
                            logger.info("Another worker holds the ITDR poll lock — skipping cycle")
                            time.sleep(interval * 60)
                            continue
                        res = poll_all_tenants()
                        logger.info("ITDR poll cycle: %s", {k: res.get(k) for k in
                                    ("tenants_polled", "sign_ins", "audit_logs", "risk_detections", "detections")})
                except Exception as e:
                    logger.error("ITDR poll cycle failed: %s", e)
                time.sleep(interval * 60)

        _poller_thread = threading.Thread(target=_loop, daemon=True, name="itdr-poller")
        _poller_thread.start()
        return True