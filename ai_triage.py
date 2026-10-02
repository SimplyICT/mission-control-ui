"""Alert triage engine — supports LLM (OpenAI-compatible or Ollama), correlated batch triage, and rule-based fallback."""
import json
import logging
import os
from datetime import datetime, timezone

import requests

try:
    # Optional SOC skill library; triage must keep working without it
    # (missing module, missing index, or a broken index).
    import skills_lib
except Exception:  # pragma: no cover - depends on deploy layout
    skills_lib = None

logger = logging.getLogger("ai_triage")

AI_API_URL = os.getenv("AI_API_URL", "").strip()
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")

DEFAULT_RESPONSE = {
    "analysis": "Unable to analyze alert automatically.",
    "confidence": 0.5,
    "recommended_action": "escalate",
    "mitre_technique": "",
    "response_plan": ["Review alert manually"],
    "false_positive_likelihood": "unknown",
}

# ═══════════════════════════════════════════════════════
#  Single-alert prompt (kept for backward compat)
# ═══════════════════════════════════════════════════════

ALERT_TRIAGE_PROMPT = """You are a SOC triage analyst. Analyze this security alert and return ONLY valid JSON.

Alert:
- ID: {id}
- Level: {level} (0-15, higher = more severe)
- Title: {title}
- Description: {description}
- Source: {source}
- Rule ID: {rule_id}
- Similar alerts in 24h: {similar_count}

Return JSON with these fields:
- "analysis": brief 2-3 sentence analysis
- "confidence": 0.0 to 1.0 (how confident you are in your assessment)
- "recommended_action": "resolve" or "escalate"
- "mitre_technique": MITRE ATT&CK technique ID if applicable, or empty string
- "response_plan": list of recommended action strings (2-4 items)
- "false_positive_likelihood": "low", "medium", or "high"
{playbooks}
JSON:"""

# ═══════════════════════════════════════════════════════
#  Correlated batch prompt — multiple related alerts in one call
# ═══════════════════════════════════════════════════════

BATCH_TRIAGE_PROMPT = """You are a SOC triage analyst. Below are {count} security alerts from the SAME source within a short time window.

Analyze them TOGETHER and determine:
1. Are they the same ongoing incident, separate incidents, or noise?
2. What is the overall severity and MITRE tactic?
3. What action should the SOC take?

Alerts:
{details}

Return ONLY valid JSON with these fields:
- "incident_title": short title describing the overall situation
- "incident_type": "same_attack", "separate_incidents", or "noise"
- "analysis": 2-3 sentence analysis of the correlated alerts
- "confidence": 0.0 to 1.0 (how confident in this assessment)
- "recommended_action": "resolve" or "escalate"
- "mitre_technique": MITRE ATT&CK technique ID or empty string
- "mitre_tactic": MITRE ATT&CK tactic name or empty string
- "max_severity": highest severity among the group ("low", "medium", "high", "critical")
- "false_positive_likelihood": "low", "medium", or "high"
- "response_plan": list of recommended action strings (2-4 items)
{playbooks}
JSON:"""


# ═══════════════════════════════════════════════════════
#  LLM call helpers
# ═══════════════════════════════════════════════════════

def _call_llm(prompt: str, max_tokens: int = 500) -> str:
    """Try LLM call via OpenAI-compatible API. Returns empty string on failure."""
    if not AI_API_URL:
        return ""

    headers = {"Content-Type": "application/json"}
    if AI_API_KEY:
        headers["Authorization"] = f"Bearer {AI_API_KEY}"

    try:
        resp = requests.post(
            AI_API_URL,
            json={
                "model": AI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": max_tokens,
            },
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        logger.warning("LLM API call failed: %s", e)
        return ""


def _parse_response(raw: str, default: dict | None = None) -> dict:
    """Parse LLM JSON response with fallback defaults."""
    if default is None:
        default = DEFAULT_RESPONSE
    try:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1]) if len(lines) > 2 else lines[-1]
            cleaned = cleaned.strip()
        data = json.loads(cleaned)
        return {
            "analysis": data.get("analysis", default["analysis"]),
            "confidence": float(data.get("confidence", default["confidence"])),
            "recommended_action": data.get("recommended_action", default["recommended_action"]),
            "mitre_technique": data.get("mitre_technique", default.get("mitre_technique", "")),
            "response_plan": data.get("response_plan", default["response_plan"]),
            "false_positive_likelihood": data.get("false_positive_likelihood", default["false_positive_likelihood"]),
        }
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        logger.warning("Failed to parse LLM response: %s — raw: %s", e, raw[:200])
        return dict(default)


# ═══════════════════════════════════════════════════════
#  Rule-based fallback (single alert)
# ═══════════════════════════════════════════════════════

_FP_KEYWORDS = [
    "information", "audit success", "permission change",
    "profile changed", "eventlog", "brother brlog",
]
_ESC_KEYWORDS = [
    "failed login", "brute force", "malware", "ransomware",
    "exploit", "cve-", "trojan", "backdoor", "unauthorized",
]


def _rule_based_triage(alert: dict) -> dict:
    """Fallback rule-based triage when no LLM is available."""
    level = alert.get("level", 0)
    title = (alert.get("title") or "").lower()
    desc = (alert.get("description") or "").lower()

    fp_match = any(k in title or k in desc for k in _FP_KEYWORDS)
    esc_match = any(k in title or k in desc for k in _ESC_KEYWORDS)

    if fp_match and level <= 11:
        return {
            "analysis": "Likely false positive based on alert content.",
            "confidence": 0.85,
            "recommended_action": "resolve",
            "mitre_technique": "",
            "response_plan": ["Verify alert context", "Update rules if needed"],
            "false_positive_likelihood": "high",
        }

    if level <= 7:
        return {
            "analysis": "Low severity alert. Auto-resolving.",
            "confidence": 0.8,
            "recommended_action": "resolve",
            "mitre_technique": "",
            "response_plan": ["Log for daily digest"],
            "false_positive_likelihood": "low",
        }

    if level <= 11:
        return {
            "analysis": "Medium severity alert. Escalating for review.",
            "confidence": 0.6,
            "recommended_action": "escalate",
            "mitre_technique": "",
            "response_plan": ["Review alert details", "Check related events",
                              "Escalate if pattern detected"],
            "false_positive_likelihood": "medium",
        }

    if esc_match:
        return {
            "analysis": "Alert matches escalation patterns. Creating case.",
            "confidence": 0.75,
            "recommended_action": "escalate",
            "mitre_technique": "T1078",
            "response_plan": ["Investigate source", "Isolate affected systems",
                              "Alert SOC team"],
            "false_positive_likelihood": "low",
        }

    return {
        "analysis": f"High severity alert (level {level}). Requires investigation.",
        "confidence": 0.7,
        "recommended_action": "escalate",
        "mitre_technique": "",
        "response_plan": ["Investigate immediately", "Alert SOC team",
                          "Review related alerts"],
        "false_positive_likelihood": "low",
    }


# ═══════════════════════════════════════════════════════
#  Rule-based fallback for a group of correlated alerts
# ═══════════════════════════════════════════════════════

def _rule_based_batch_triage(alerts: list[dict]) -> dict:
    """Fallback for a batch: picks the highest-severity alert and triages it."""
    if not alerts:
        return dict(DEFAULT_RESPONSE)
    # Pick the highest-level alert as the representative
    worst = max(alerts, key=lambda a: a.get("level", 0))
    single = _rule_based_triage(worst)
    # Boost confidence slightly if there are multiple related alerts
    if len(alerts) > 1:
        single["confidence"] = min(single["confidence"] + 0.1, 1.0)
        single["analysis"] = (
            f"[{len(alerts)} correlated alerts] {single['analysis']}"
        )
    return single


# ═══════════════════════════════════════════════════════
#  Skill-library grounding — optional analyst playbooks
# ═══════════════════════════════════════════════════════

_PLAYBOOK_HEADER = (
    "Relevant analyst playbook(s) from the SOC skill library "
    "(use this workflow to structure your analysis; do not quote them verbatim):"
)
_PLAYBOOK_MAX_SKILLS = 2
_PLAYBOOK_DESC_CHARS = 400
_PLAYBOOK_DESC_MIN = 120
_PLAYBOOK_MAX_CHARS = 900

# Same tolerant sources used elsewhere for MITRE ids.
_TECHNIQUE_KEYS = ("mitre", "mitreTechniques", "mitre_attack")


def _entry_prefix(name: str, subdomain: str) -> str:
    return f"- {name} [{subdomain}]: "


def _clip(text: str, limit: int) -> str:
    """Truncate to a char budget without slicing a word when avoidable."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    space = cut.rfind(" ")
    return cut[:space] if space > limit - 40 else cut


def _extract_techniques(alert: dict) -> list[str]:
    """Collect MITRE technique ids from an alert.

    Values may be a list or a comma-separated string; output is de-duplicated.
    """
    found: list[str] = []
    for key in _TECHNIQUE_KEYS:
        val = alert.get(key)
        if not val:
            continue
        items = val if isinstance(val, (list, tuple)) else str(val).split(",")
        for item in items:
            tech = str(item).strip().upper()
            if tech and tech not in found:
                found.append(tech)
    return found


def _playbook_grounding(
    techniques: list[str],
    detection_type: str,
    limit: int = _PLAYBOOK_MAX_SKILLS,
) -> tuple[str, list[str]]:
    """Look up matching defensive playbooks. Returns (prompt_block, names).

    Never raises: triage falls back to its ungrounded prompt on any failure.
    """
    if skills_lib is None:
        return "", []
    try:
        matches = skills_lib.match(
            techniques=techniques,
            detection_type=detection_type or "",
            limit=limit,
        )
    except Exception as e:
        logger.warning("Skill library match failed: %s", e)
        return "", []

    items: list[tuple[str, str, str]] = []
    for m in (matches or [])[:_PLAYBOOK_MAX_SKILLS]:
        if not isinstance(m, dict):
            continue
        name = str(m.get("name") or "").strip()
        if not name:
            continue
        subdomain = str(m.get("subdomain") or "").strip()
        desc = " ".join(str(m.get("description") or "").split())
        items.append((name, subdomain, desc))
        if len(items) >= _PLAYBOOK_MAX_SKILLS:
            break

    if not items:
        return "", []

    # Fit up to two entries plus the header inside the char cap: shrink the
    # descriptions first, and only drop the second entry if nothing useful fits.
    for kept in range(len(items), 0, -1):
        head = items[:kept]
        overhead = len(_PLAYBOOK_HEADER) + 1 + sum(
            len(_entry_prefix(n, s)) + 1 for n, s, _ in head)
        budget = _PLAYBOOK_MAX_CHARS - overhead
        if kept > 1 and budget < kept * _PLAYBOOK_DESC_MIN:
            continue
        per_desc = min(_PLAYBOOK_DESC_CHARS, max(_PLAYBOOK_DESC_MIN, budget // kept))
        block = _PLAYBOOK_HEADER + "\n" + "\n".join(
            f"{_entry_prefix(n, s)}{_clip(d, per_desc)}" for n, s, d in head)
        return block[:_PLAYBOOK_MAX_CHARS].rstrip(), [n for n, _, _ in head]

    return "", []


# ═══════════════════════════════════════════════════════
#  Public API — single alert
# ═══════════════════════════════════════════════════════

def triage_alert(alert: dict) -> dict:
    """Analyze a single alert.

    1st: Try LLM (OpenAI-compatible API). Falls back to rule-based triage.
    Both paths carry "grounded_by": names of matched SOC playbooks (possibly []).
    """
    filled = {
        "id": alert.get("id", "unknown"),
        "level": alert.get("level", 0),
        "title": alert.get("title", alert.get("name", "")),
        "description": alert.get("description", alert.get("message", "")),
        "source": alert.get("source", alert.get("agent_name", "unknown")),
        "rule_id": alert.get("rule_id", alert.get("rule", 0)),
        "similar_count": alert.get("similar_count_24h", 0),
    }

    playbook_block, grounded_by = _playbook_grounding(
        _extract_techniques(alert),
        alert.get("detection_type") or filled["source"],
    )

    prompt = ALERT_TRIAGE_PROMPT.format(playbooks=playbook_block, **filled)
    raw = _call_llm(prompt)

    if raw:
        parsed = _parse_response(raw)
        parsed["grounded_by"] = grounded_by
        logger.info("LLM triage for %s: action=%s confidence=%.2f grounded_by=%s",
                    filled["id"], parsed["recommended_action"], parsed["confidence"],
                    grounded_by)
        return parsed

    fallback = _rule_based_triage(alert)
    fallback["grounded_by"] = grounded_by
    logger.info("Rule-based triage for %s (level %d): action=%s confidence=%.2f",
                filled["id"], filled["level"], fallback["recommended_action"], fallback["confidence"])
    return fallback


# ═══════════════════════════════════════════════════════
#  Public API — uncorrelated batch (legacy)
# ═══════════════════════════════════════════════════════

def triage_batch(alerts: list[dict]) -> list[dict]:
    """Triage multiple unrelated alerts (one LLM call per alert)."""
    return [triage_alert(a) for a in alerts]


# ═══════════════════════════════════════════════════════
#  Public API — correlated batch (NEW)
# ═══════════════════════════════════════════════════════

def triage_batch_correlated(alerts: list[dict]) -> dict:
    """Triage a group of correlated alerts (same source, short time window)
    with a SINGLE LLM call. Returns a merged analysis dict with extra keys:

    Keys returned (superset of DEFAULT_RESPONSE):
      - incident_title, incident_type, mitre_tactic, max_severity
      - grounded_by: names of matched SOC playbooks (possibly [])
      - + all fields from DEFAULT_RESPONSE
    """
    if not alerts:
        empty = dict(DEFAULT_RESPONSE)
        empty["grounded_by"] = []
        return empty

    # Build readable detail lines for the prompt
    details = []
    for i, a in enumerate(alerts, 1):
        ts = a.get("timestamp", a.get("first_seen_at", "?"))
        level = a.get("level", 0)
        title = a.get("title", a.get("name", "?"))[:80]
        desc = a.get("description", a.get("message", ""))[:120]
        rule = a.get("rule_id", a.get("rule", "?"))
        details.append(
            f"  [{i}] Time={ts} Level={level} Rule={rule}\n"
            f"       Title: {title}\n"
            f"       Description: {desc}"
        )

    # Union of techniques across the group; first usable detection_type/source wins.
    techniques: list[str] = []
    for a in alerts:
        for tech in _extract_techniques(a):
            if tech not in techniques:
                techniques.append(tech)
    detection_type = ""
    for a in alerts:
        detection_type = a.get("detection_type") or a.get("source") or a.get("agent_name") or ""
        if detection_type:
            break
    playbook_block, grounded_by = _playbook_grounding(techniques, detection_type)

    prompt = BATCH_TRIAGE_PROMPT.format(
        count=len(alerts),
        details="\n".join(details),
        playbooks=playbook_block,
    )

    raw = _call_llm(prompt, max_tokens=600)

    if raw:
        parsed = _parse_response(raw)
        # Extract batch-specific fields
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]) if len(lines) > 2 else lines[-1]
                cleaned = cleaned.strip()
            data = json.loads(cleaned)
            parsed["incident_title"] = data.get("incident_title", "")
            parsed["incident_type"] = data.get("incident_type", "separate_incidents")
            parsed["mitre_tactic"] = data.get("mitre_tactic", "")
            parsed["max_severity"] = data.get("max_severity", "medium")
        except (json.JSONDecodeError, ValueError, TypeError):
            parsed["incident_title"] = ""
            parsed["incident_type"] = "separate_incidents"
            parsed["mitre_tactic"] = ""
            parsed["max_severity"] = "medium"

        parsed["grounded_by"] = grounded_by
        logger.info(
            "LLM batch triage for %d alerts: incident_type=%s confidence=%.2f grounded_by=%s",
            len(alerts), parsed.get("incident_type", "?"), parsed["confidence"],
            grounded_by,
        )
        return parsed

    fallback = _rule_based_batch_triage(alerts)
    # Add batch-only fields with defaults
    fallback["incident_title"] = ""
    fallback["incident_type"] = "separate_incidents"
    fallback["mitre_tactic"] = ""
    fallback["max_severity"] = "medium"
    fallback["grounded_by"] = grounded_by
    logger.info(
        "Rule-based batch triage for %d alerts: action=%s confidence=%.2f",
        len(alerts), fallback["recommended_action"], fallback["confidence"],
    )
    return fallback
