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

from itdr_detections import run_detections

logger = logging.getLogger("itdr")

# ── Config ──────────────────────────────────────────────────────────────────
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ITDR_STORE = Path(__file__).parent / "itdr_events.json"
ITDR_CASES = Path(__file__).parent / "itdr_cases.json"
TENANTS_FILE = Path(__file__).parent / "itdr_tenants.json"
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


def get_tenants() -> list[dict]:
    """All registered tenants plus the legacy synth tenant if nothing is configured."""
    tenants = _load_tenants()
    if not tenants:
        legacy = _legacy_default_tenant()
        if legacy:
            tenants = [legacy]
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


def _tenant_credentials(tenant: dict) -> dict:
    """Resolve client id/secret/tenant id for a tenant from env vars."""
    if not tenant:
        return {}
    tid = tenant.get("id", "")
    if tid == "default":
        return dict(LEGACY_CREDS)
    prefix = (tenant.get("env_prefix") or tid).upper()
    creds = {
        "tenant_id": os.getenv(f"ITDR_{prefix}_TENANT_ID", "").strip() or (tenant.get("tenant_id") or "").strip(),
        "client_id": os.getenv(f"ITDR_{prefix}_CLIENT_ID", "").strip(),
        "client_secret": os.getenv(f"ITDR_{prefix}_CLIENT_SECRET", "").strip(),
    }
    return creds


def is_configured(tenant: dict) -> bool:
    creds = _tenant_credentials(tenant)
    return all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")])


# ═══════════════════════════════════════════════════════
#  Auth (per-tenant token cache)
# ═══════════════════════════════════════════════════════

def get_token(tenant: dict | None = None) -> str:
    """Get Microsoft Graph access token via client credentials flow (per tenant)."""
    if tenant is None:
        tenant = _legacy_default_tenant()
    if not tenant:
        return ""
    tid = tenant.get("id", "")
    cached = _token_cache.get(tid)
    if cached and cached.get("value") and time.time() < cached.get("expires_at", 0) - 60:
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
        tenants_out.append({
            "id": tid,
            "name": t.get("name", tid),
            "tenant_id": t.get("tenant_id", ""),
            "org_id": t.get("org_id", "default"),
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

def _last_event_ts(tenant_id: str) -> str | None:
    """Newest stored event timestamp for a tenant (Graph filter window base)."""
    for e in _load_events():
        if (e.get("tenant_id") or "default") == tenant_id:
            ts = e.get("created_at") or e.get("detected_at") or ""
            if ts:
                return ts
    return None


def _mark_poll(tenant_id: str, status: str, error: str | None = None):
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

    # Polling window: last stored event for this tenant, else 24h ago.
    since = _last_event_ts(tenant_id)
    if not since:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat() + "Z"

    results = {"tenant_id": tenant_id, "sign_ins": 0, "audit_logs": 0,
               "risk_detections": 0, "events_stored": 0, "detections": 0}
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

    _mark_poll(tenant_id, "ok")
    results["status"] = "ok"
    return results


def _create_cases_for_detections(detections: list[dict], tenant: dict) -> int:
    """Persist new detections as open cases, deduped by (tenant, type, user) within 24h."""
    created = 0
    now = datetime.now(timezone.utc)
    existing = get_cases()
    for det in detections:
        user = det.get("user", "")
        dtype = det.get("detection_type", "")
        key = (tenant.get("id", ""), dtype, user)
        dup = False
        for c in existing:
            if (c.get("tenant_id"), c.get("detection_type"), c.get("user")) == key \
                    and c.get("status") in ("open", "investigating"):
                try:
                    ts = datetime.fromisoformat(str(c.get("created_at", "")).replace("Z", "+00:00"))
                    if now - ts <= timedelta(hours=24):
                        dup = True
                        break
                except Exception:
                    dup = True  # unparseable ts → treat as recent to avoid spam
                    break
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