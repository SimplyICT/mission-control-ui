"""Alert triage engine — supports LLM (OpenAI-compatible or Ollama) and rule-based fallback."""
import json
import logging
import os
import requests

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
    "false_positive_likelihood": "unknown"
}

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

JSON:"""


def _rule_based_triage(alert: dict) -> dict:
    """Fallback rule-based triage when no LLM is available."""
    level = alert.get("level", 0)
    title = (alert.get("title") or "").lower()
    desc = (alert.get("description") or "").lower()

    false_positive_keywords = ["information", "audit success", "permission change",
                                "profile changed", "eventlog", "brother brlog"]
    escalation_keywords = ["failed login", "brute force", "malware", "ransomware",
                           "exploit", "cve-", "trojan", "backdoor", "unauthorized"]

    fp_match = any(k in title or k in desc for k in false_positive_keywords)
    esc_match = any(k in title or k in desc for k in escalation_keywords)

    if fp_match and level <= 11:
        return {
            "analysis": "Likely false positive based on alert content.",
            "confidence": 0.85,
            "recommended_action": "resolve",
            "mitre_technique": "",
            "response_plan": ["Verify alert context", "Update rules if needed"],
            "false_positive_likelihood": "high"
        }

    if level <= 7:
        return {
            "analysis": "Low severity alert. Auto-resolving.",
            "confidence": 0.8,
            "recommended_action": "resolve",
            "mitre_technique": "",
            "response_plan": ["Log for daily digest"],
            "false_positive_likelihood": "low"
        }

    if level <= 11:
        return {
            "analysis": "Medium severity alert. Escalating for review.",
            "confidence": 0.6,
            "recommended_action": "escalate",
            "mitre_technique": "",
            "response_plan": ["Review alert details", "Check related events",
                              "Escalate if pattern detected"],
            "false_positive_likelihood": "medium"
        }

    if esc_match:
        return {
            "analysis": "Alert matches escalation patterns. Creating case.",
            "confidence": 0.75,
            "recommended_action": "escalate",
            "mitre_technique": "T1078",
            "response_plan": ["Investigate source", "Isolate affected systems",
                              "Alert SOC team"],
            "false_positive_likelihood": "low"
        }

    return {
        "analysis": f"High severity alert (level {level}). Requires investigation.",
        "confidence": 0.7,
        "recommended_action": "escalate",
        "mitre_technique": "",
        "response_plan": ["Investigate immediately", "Alert SOC team",
                          "Review related alerts"],
        "false_positive_likelihood": "low"
    }


def _call_llm(prompt: str) -> str:
    """Try LLM call via OpenAI-compatible API. Returns empty string on failure."""
    if not AI_API_URL:
        return ""

    headers = {"Content-Type": "application/json"}
    if AI_API_KEY:
        headers["Authorization"] = f"Bearer {AI_API_KEY}"

    try:
        # OpenAI-compatible chat completions endpoint
        resp = requests.post(
            AI_API_URL,
            json={
                "model": AI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 300,
            },
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        logger.warning("LLM API call failed: %s", e)
        return ""


def _parse_response(raw: str) -> dict:
    """Parse LLM JSON response with fallback defaults."""
    try:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1]) if len(lines) > 2 else lines[-1]
            cleaned = cleaned.strip()
        data = json.loads(cleaned)
        return {
            "analysis": data.get("analysis", DEFAULT_RESPONSE["analysis"]),
            "confidence": float(data.get("confidence", DEFAULT_RESPONSE["confidence"])),
            "recommended_action": data.get("recommended_action", DEFAULT_RESPONSE["recommended_action"]),
            "mitre_technique": data.get("mitre_technique", DEFAULT_RESPONSE["mitre_technique"]),
            "response_plan": data.get("response_plan", DEFAULT_RESPONSE["response_plan"]),
            "false_positive_likelihood": data.get("false_positive_likelihood", DEFAULT_RESPONSE["false_positive_likelihood"]),
        }
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        logger.warning("Failed to parse LLM response: %s — raw: %s", e, raw[:200])
        return dict(DEFAULT_RESPONSE)


def triage_alert(alert: dict) -> dict:
    """Analyze a single alert.

    1st: Try LLM (OpenAI-compatible API). Falls back to rule-based triage.
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

    prompt = ALERT_TRIAGE_PROMPT.format(**filled)
    raw = _call_llm(prompt)

    if raw:
        parsed = _parse_response(raw)
        logger.info("LLM triage for %s: action=%s confidence=%.2f",
                    filled["id"], parsed["recommended_action"], parsed["confidence"])
        return parsed

    fallback = _rule_based_triage(alert)
    logger.info("Rule-based triage for %s (level %d): action=%s confidence=%.2f",
                filled["id"], filled["level"], fallback["recommended_action"], fallback["confidence"])
    return fallback


def triage_batch(alerts: list[dict]) -> list[dict]:
    """Triage multiple alerts."""
    return [triage_alert(a) for a in alerts]
