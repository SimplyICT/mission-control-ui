"""Daily SOC digest — generates AI-powered summary of alert activity."""
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from ai_triage import _call_llm

logger = logging.getLogger("ai_digest")

BASE_DIR = Path(__file__).resolve().parent
AUDIT_FILE = BASE_DIR / "ai_audit_log.json"
CASES_FILE = BASE_DIR / "ai_cases.json"

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
_SUPABASE_HEADERS = {}
if SUPABASE_URL and SUPABASE_KEY:
    _SUPABASE_HEADERS = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }

DIGEST_PROMPT = """You are a SOC shift lead writing a daily digest. Based on the following data from the last 24 hours, write a concise 3-5 sentence summary for the SOC team.

Total alerts processed: {total_alerts}
Auto-resolved: {auto_resolved}
Cases created: {cases_created}
Cases awaiting approval: {awaiting_approval}
Most common alert level: {most_common_level}

Alert breakdown by level:
{alert_breakdown}

Write a professional, actionable summary:"""


def _read_json(path: Path) -> list:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _fetch_24h_stats() -> dict:
    """Query local JSON or Supabase for the past 24 hours."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    # Try Supabase first
    if SUPABASE_URL and SUPABASE_KEY:
        import requests
        try:
            resp = requests.get(
                f"{SUPABASE_URL}/rest/v1/soc_audit_log",
                headers=_SUPABASE_HEADERS,
                params={"select": "alert_level,action", "created_at": f"gte.{cutoff}", "limit": "1000"},
                timeout=10,
            )
            if resp.ok:
                entries = resp.json()
                total = len(entries)
                auto_resolved = sum(1 for e in entries if e.get("action") == "auto_resolve")
                cases_created = sum(1 for e in entries if e.get("action") == "case_created")
                levels = [e.get("alert_level", 0) for e in entries if e.get("alert_level") is not None]
                return _build_stats(total, auto_resolved, cases_created, levels)
        except Exception:
            pass

    # Fall back to local JSON
    entries = [e for e in _read_json(AUDIT_FILE) if e.get("created_at", "") >= cutoff]
    total = len(entries)
    auto_resolved = sum(1 for e in entries if e.get("action") == "auto_resolve")
    cases_created = sum(1 for e in entries if e.get("action") == "case_created")
    levels = [e.get("alert_level", 0) for e in entries if e.get("alert_level") is not None]
    return _build_stats(total, auto_resolved, cases_created, levels)


def _build_stats(total: int, auto_resolved: int, cases_created: int, levels: list) -> dict:
    level_counts = {}
    for lv in levels:
        label = "critical" if lv >= 15 else "high" if lv >= 12 else "medium" if lv >= 7 else "low"
        level_counts[label] = level_counts.get(label, 0) + 1

    most_common = max(level_counts, key=level_counts.get) if level_counts else "none"
    alert_breakdown = "\n".join(f"- {k}: {v}" for k, v in sorted(level_counts.items()))

    # Count awaiting cases
    cases = _read_json(CASES_FILE) if not (SUPABASE_URL and SUPABASE_KEY) else []
    awaiting = sum(1 for c in cases if c.get("status") == "awaiting_approval")

    if SUPABASE_URL and SUPABASE_KEY:
        import requests
        try:
            resp = requests.get(
                f"{SUPABASE_URL}/rest/v1/soc_cases",
                headers=_SUPABASE_HEADERS,
                params={"select": "status", "status": "eq.awaiting_approval", "limit": "1"},
                timeout=5,
            )
            if resp.ok:
                awaiting = len(resp.json())
        except Exception:
            pass

    return {
        "total_alerts": total,
        "auto_resolved": auto_resolved,
        "cases_created": cases_created,
        "awaiting_approval": awaiting,
        "most_common_level": most_common,
        "alert_breakdown": alert_breakdown or "No alerts in this period",
    }


def generate_digest() -> str:
    """Generate a daily SOC digest text using the LLM."""
    stats = _fetch_24h_stats()
    if not stats or stats.get("total_alerts", 0) == 0:
        return "No alert activity in the last 24 hours."

    prompt = DIGEST_PROMPT.format(**stats)
    raw = _call_llm(prompt)
    if raw:
        return raw.strip()
    return "Digest generation failed."
