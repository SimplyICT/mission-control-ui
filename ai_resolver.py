"""Auto-resolution and case creation for AI-triaged alerts.

Stores cases and audit logs in local JSON files as fallback.
Automatically uses Supabase tables when they exist (checked at startup).
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("ai_resolver")

BASE_DIR = Path(__file__).resolve().parent
CASES_FILE = BASE_DIR / "ai_cases.json"
AUDIT_FILE = BASE_DIR / "ai_audit_log.json"

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
_SUPABASE_HEADERS = {}
if SUPABASE_URL and SUPABASE_KEY:
    _SUPABASE_HEADERS = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }

_USE_SUPABASE = None  # lazy-init, checked on first use


def _check_supabase() -> bool:
    """Check if Supabase tables exist and are accessible."""
    global _USE_SUPABASE
    if _USE_SUPABASE is not None:
        return _USE_SUPABASE
    if not SUPABASE_URL or not SUPABASE_KEY:
        _USE_SUPABASE = False
        return False
    try:
        import requests
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/soc_cases",
            headers=_SUPABASE_HEADERS,
            params={"select": "count", "limit": "1"},
            timeout=5,
        )
        _USE_SUPABASE = resp.ok
        if not _USE_SUPABASE:
            logger.info("Supabase soc_cases table not found, using local JSON storage")
        else:
            logger.info("Using Supabase for case storage")
        return _USE_SUPABASE
    except Exception as e:
        logger.warning("Supabase check failed: %s — using local JSON", e)
        _USE_SUPABASE = False
        return False


# ── Local JSON helpers ──────────────────────────────────────────────────


def _read_json(path: Path) -> list:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _write_json(path: Path, data: list):
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _gen_id() -> str:
    import uuid
    return str(uuid.uuid4())


# ── Audit Log ──────────────────────────────────────────────────────────


def _log_action_local(alert_id: str, alert_title: str, alert_level: int,
                      action: str, confidence: float, analysis: str):
    entries = _read_json(AUDIT_FILE)
    entries.append({
        "id": _gen_id(),
        "alert_id": alert_id,
        "alert_title": alert_title,
        "alert_level": alert_level,
        "action": action,
        "confidence": confidence,
        "analysis": analysis,
        "ai_model": "llama3.2:3b",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    _write_json(AUDIT_FILE, entries)
    return True


def _log_action_supabase(alert_id: str, alert_title: str, alert_level: int,
                         action: str, confidence: float, analysis: str) -> bool:
    import requests
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/soc_audit_log",
            headers=_SUPABASE_HEADERS,
            json={
                "alert_id": alert_id,
                "alert_title": alert_title,
                "alert_level": alert_level,
                "action": action,
                "confidence": confidence,
                "analysis": analysis,
                "ai_model": "llama3.2:3b",
            },
            timeout=10,
        )
        return resp.ok
    except Exception as e:
        logger.error("Failed to write audit log to Supabase: %s", e)
        return False


def log_action(alert_id: str, alert_title: str, alert_level: int,
               action: str, confidence: float, analysis: str) -> bool:
    if _check_supabase():
        return _log_action_supabase(alert_id, alert_title, alert_level,
                                    action, confidence, analysis)
    return _log_action_local(alert_id, alert_title, alert_level,
                             action, confidence, analysis)


# ── Auto-resolve ───────────────────────────────────────────────────────


def auto_resolve(alert: dict, analysis: dict) -> bool:
    """Auto-resolve an alert after AI analysis.

    Logs the action and optionally updates alert status via internal API.
    """
    alert_id = alert.get("id", "")
    alert_title = alert.get("title", alert.get("name", ""))
    alert_level = alert.get("level", 0)
    confidence = analysis.get("confidence", 0.5)
    analysis_text = analysis.get("analysis", "")

    log_action(alert_id, alert_title, alert_level,
               "auto_resolve", confidence, analysis_text)

    try:
        import requests
        api_key = os.getenv("MISSION_API_KEY", "mission-test-key-123")
        resp = requests.post(
            f"http://127.0.0.1:8000/api/v1/alerts/{alert_id}/resolve",
            headers={"x-api-key": api_key},
            timeout=10,
            json={
                "reason": f"AI auto-resolved (confidence: {confidence:.2f}): {analysis_text}"
            },
        )
        if resp.ok:
            logger.info("Auto-resolved alert %s (confidence=%.2f)", alert_id, confidence)
            return True
        logger.warning("Failed to resolve alert %s: HTTP %d", alert_id, resp.status_code)
        return False
    except Exception as e:
        logger.error("Error resolving alert %s: %s", alert_id, e)
        return False


# ── Case Creation ──────────────────────────────────────────────────────


def _create_case_local(alerts: list[dict], analysis: dict) -> str | None:
    cases = _read_json(CASES_FILE)
    max_level = max((a.get("level", 0) for a in alerts), default=0)
    severity_labels = {15: "critical", 14: "high", 13: "high", 12: "high",
                       11: "medium", 10: "medium", 9: "medium", 8: "medium",
                       7: "medium", 6: "low", 5: "low", 4: "low",
                       3: "low", 2: "low", 1: "low", 0: "low"}
    severity = severity_labels.get(max_level, "low")

    case = {
        "id": _gen_id(),
        "title": max((a.get("title", "") for a in alerts), key=len) or f"Multiple alerts ({severity})",
        "severity": severity,
        "status": "awaiting_approval",
        "alert_ids": [a.get("id", "") for a in alerts if a.get("id")],
        "ai_analysis": analysis.get("analysis", ""),
        "confidence": analysis.get("confidence", 0.5),
        "mitre_technique": analysis.get("mitre_technique", ""),
        "response_plan": analysis.get("response_plan", []),
        "entities": [{"source": a.get("source", a.get("agent_name", ""))} for a in alerts if a.get("source") or a.get("agent_name")],
        "events": [{"type": "created", "timestamp": datetime.now(timezone.utc).isoformat(), "detail": "Case created by AI triage"}],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    cases.insert(0, case)
    _write_json(CASES_FILE, cases)

    for a in alerts:
        log_action(a.get("id", ""), a.get("title", ""), a.get("level", 0),
                    "case_created", analysis.get("confidence", 0.5),
                    analysis.get("analysis", ""))

    logger.info("Created case %s for %d alerts (confidence=%.2f)",
                case["id"], len(alerts), analysis.get("confidence", 0.5))
    return case["id"]


def _create_case_supabase(alerts: list[dict], analysis: dict) -> str | None:
    import requests
    max_level = max((a.get("level", 0) for a in alerts), default=0)
    severity_labels = {15: "critical", 14: "high", 13: "high", 12: "high",
                       11: "medium", 10: "medium", 9: "medium", 8: "medium",
                       7: "medium", 6: "low", 5: "low", 4: "low",
                       3: "low", 2: "low", 1: "low", 0: "low"}
    severity = severity_labels.get(max_level, "low")

    case_data = {
        "title": max((a.get("title", "") for a in alerts), key=len) or f"Multiple alerts ({severity})",
        "severity": severity,
        "status": "awaiting_approval",
        "alert_ids": json.dumps([a.get("id", "") for a in alerts if a.get("id")]),
        "ai_analysis": analysis.get("analysis", ""),
        "confidence": analysis.get("confidence", 0.5),
        "mitre_technique": analysis.get("mitre_technique", ""),
        "response_plan": json.dumps(analysis.get("response_plan", [])),
        "entities": json.dumps([{"source": a.get("source", a.get("agent_name", ""))} for a in alerts if a.get("source") or a.get("agent_name")]),
    }

    try:
        resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/soc_cases",
            headers=_SUPABASE_HEADERS,
            json=case_data,
            timeout=10,
        )
        if resp.ok:
            case_id = resp.json().get("id", "")
            for a in alerts:
                log_action(a.get("id", ""), a.get("title", ""), a.get("level", 0),
                           "case_created", analysis.get("confidence", 0.5),
                           analysis.get("analysis", ""))
            logger.info("Created case %s for %d alerts (confidence=%.2f)",
                        case_id, len(alerts), analysis.get("confidence", 0.5))
            return case_id
        logger.warning("Supabase case creation failed: HTTP %d — %s", resp.status_code, resp.text[:200])
        return None
    except Exception as e:
        logger.error("Failed to create case in Supabase: %s", e)
        return None


def create_case(alerts: list[dict], analysis: dict) -> str | None:
    """Create a SOC case from AI-analyzed alerts.

    Returns the case ID if successful, None otherwise.
    """
    if _check_supabase():
        return _create_case_supabase(alerts, analysis)
    return _create_case_local(alerts, analysis)


# ── Read / List ────────────────────────────────────────────────────────


def list_cases() -> list[dict]:
    """Return all cases, newest first."""
    if _check_supabase():
        import requests
        try:
            resp = requests.get(
                f"{SUPABASE_URL}/rest/v1/soc_cases",
                headers=_SUPABASE_HEADERS,
                params={"order": "created_at.desc"},
                timeout=10,
            )
            if resp.ok:
                return resp.json()
        except Exception as e:
            logger.error("Failed to list cases from Supabase: %s", e)
    return _read_json(CASES_FILE)


def get_case(case_id: str) -> dict | None:
    """Return a single case by ID."""
    if _check_supabase():
        import requests
        try:
            resp = requests.get(
                f"{SUPABASE_URL}/rest/v1/soc_cases",
                headers=_SUPABASE_HEADERS,
                params={"id": f"eq.{case_id}"},
                timeout=10,
            )
            if resp.ok and resp.json():
                return resp.json()[0]
        except Exception as e:
            logger.error("Failed to get case from Supabase: %s", e)
    for c in _read_json(CASES_FILE):
        if c.get("id") == case_id:
            return c
    return None


def update_case(case_id: str, updates: dict) -> dict | None:
    """Update a case's status/fields."""
    if _check_supabase():
        import requests
        try:
            url = f"{SUPABASE_URL}/rest/v1/soc_cases"
            params = {"id": f"eq.{case_id}"}
            updates["updated_at"] = datetime.now(timezone.utc).isoformat()
            resp = requests.patch(url, headers=_SUPABASE_HEADERS,
                                  params=params, json=updates, timeout=10)
            if resp.ok:
                return get_case(case_id)
        except Exception as e:
            logger.error("Failed to update case in Supabase: %s", e)
            return None

    cases = _read_json(CASES_FILE)
    for c in cases:
        if c.get("id") == case_id:
            c.update(updates)
            c["updated_at"] = datetime.now(timezone.utc).isoformat()
            _write_json(CASES_FILE, cases)
            return c
    return None


def get_stats() -> dict:
    """Return aggregate stats for the last 24 hours."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    if _check_supabase():
        import requests
        try:
            resp = requests.get(
                f"{SUPABASE_URL}/rest/v1/soc_cases",
                headers=_SUPABASE_HEADERS,
                params={"select": "severity,status,created_at",
                        "created_at": f"gte.{cutoff}",
                        "limit": "1000"},
                timeout=10,
            )
            if resp.ok:
                cases = resp.json()
                stats = {"last_24h": len(cases), "critical": 0, "high": 0,
                         "medium": 0, "low": 0, "resolved": 0}
                for c in cases:
                    sev = (c.get("severity") or "").lower()
                    if sev in stats:
                        stats[sev] += 1
                    if c.get("status") in ("resolved", "closed"):
                        stats["resolved"] += 1
                return stats
        except Exception as e:
            logger.error("Failed to get stats from Supabase: %s", e)

    cases = _read_json(CASES_FILE)
    recent = [c for c in cases if c.get("created_at", "") >= cutoff]
    stats = {"last_24h": len(recent), "critical": 0, "high": 0,
             "medium": 0, "low": 0, "resolved": 0}
    for c in recent:
        sev = (c.get("severity") or "").lower()
        if sev in stats:
            stats[sev] += 1
        if c.get("status") in ("resolved", "closed"):
            stats["resolved"] += 1
    return stats
