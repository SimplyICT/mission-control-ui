"""ITDR detection rules — analyzes polled identity events for threats."""
import logging
from datetime import datetime, timezone

logger = logging.getLogger("itdr_detections")

# ── Detection Rules ─────────────────────────────────────────────────────────
# Each rule is a function: (event, all_events) -> detection dict | None

DETECTIONS = []


def detection(severity: str, name: str):
    """Decorator to register a detection rule."""
    def wrapper(func):
        DETECTIONS.append({"name": name, "severity": severity, "func": func})
        return func
    return wrapper


# ═══════════════════════════════════════════════════════
#  Sign-in detections
# ═══════════════════════════════════════════════════════

@detection("critical", "MFA Fatigue Attack")
def detect_mfa_fatigue(event: dict, all_events: list[dict]) -> dict | None:
    """Detect MFA push spam: rapid sign-ins from multiple IPs.
    Only triggers if sign-ins come from 3+ different IPs in 5 min
    (real attacks use rotating IPs, token refreshes use one IP).
    """
    if event.get("source") != "signIn" or event.get("status") != 0:
        return None
    user = event.get("user", "")
    created = event.get("created_at", "")
    if not user or not created:
        return None

    recent = [
        e for e in all_events[:200]
        if e.get("user") == user
        and e.get("source") == "signIn"
        and e.get("id") != event.get("id")
    ]
    try:
        from datetime import datetime, timezone, timedelta
        window = datetime.fromisoformat(created.replace("Z", "+00:00")) - timedelta(minutes=5)
        in_window = []
        for e in recent:
            ts = e.get("created_at", "")
            try:
                ets = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if ets >= window:
                    in_window.append(e)
            except: pass

        if len(in_window) >= 15:
            # Check how many different IPs
            ips = set(e.get("ip_address", "") for e in in_window if e.get("ip_address"))
            if len(ips) >= 3:
                return {
                    "detection_type": "mfa_fatigue",
                    "severity": "critical",
                    "title": f"MFA Fatigue Attack — {user}",
                    "description": f"{len(in_window)} sign-ins from {len(ips)} different IPs in 5 minutes",
                    "user": user,
                    "timestamp": created,
                    "event_id": event.get("id", ""),
                }
    except Exception:
        pass
    return None


@detection("high", "Impossible Travel")
def detect_impossible_travel(event: dict, all_events: list[dict]) -> dict | None:
    """Detect sign-ins from geographic locations too far apart in time."""
    if event.get("source") != "signIn" or event.get("status") != 0:
        return None
    user = event.get("user", "")
    country = event.get("country", "")
    created = event.get("created_at", "")
    if not user or not country or not created:
        return None

    # Check the previous sign-in for this user
    prev = None
    for e in all_events:
        if e.get("user") == user and e.get("source") == "signIn" and e.get("id") != event.get("id"):
            prev = e
            break

    if prev and prev.get("country") and prev.get("country") != country:
        try:
            t1 = _parse_ts(created)
            t2 = _parse_ts(prev.get("created_at", ""))
            if t1 and t2:
                hours_diff = abs((t1 - t2).total_seconds()) / 3600
                if hours_diff < 6:  # Impossible to travel between countries in <6h
                    return {
                        "detection_type": "impossible_travel",
                        "severity": "high",
                        "title": f"Impossible Travel — {user}",
                        "description": f"Sign-in from {country} ({hours_diff:.0f}h after previous from {prev.get('country','?')})",
                        "user": user,
                        "timestamp": created,
                        "event_id": event.get("id", ""),
                    }
        except Exception:
            pass
    return None


@detection("high", "Anonymous IP Sign-in")
def detect_anonymous_ip(event: dict, all_events: list[dict]) -> dict | None:
    """Detect sign-ins from known anonymizer / Tor IPs."""
    if event.get("source") != "signIn" or event.get("status") != 0:
        return None
    risk = event.get("risk_level", "")
    if risk in ("medium", "high") or risk == "2":
        return {
            "detection_type": "anonymous_ip",
            "severity": "high",
            "title": f"Anonymous IP Sign-in — {event.get('user','?')}",
            "description": f"Sign-in from {event.get('ip_address','')} ({event.get('country','?')}) with risk level {risk}",
            "user": event.get("user", ""),
            "timestamp": event.get("created_at", ""),
            "event_id": event.get("id", ""),
        }
    return None


# ═══════════════════════════════════════════════════════
#  Audit log detections
# ═══════════════════════════════════════════════════════

@detection("critical", "Privileged Role Assignment")
def detect_ga_role_assignment(event: dict, all_events: list[dict]) -> dict | None:
    """Detect Global Admin / privileged role assignments."""
    if event.get("source") != "auditLog":
        return None
    activity = event.get("activity", "")
    if "Add member to role" in activity or "Add eligible member" in activity:
        targets = event.get("target_resources", [])
        for t in targets:
            if "admin" in t.lower() or "global" in t.lower():
                return {
                    "detection_type": "privileged_role",
                    "severity": "critical",
                    "title": f"Privileged Role Assigned — {event.get('user','?')}",
                    "description": f"{activity}: {', '.join(targets)}",
                    "user": event.get("user", ""),
                    "timestamp": event.get("created_at", ""),
                    "event_id": event.get("id", ""),
                }
    return None


@detection("high", "Mail Forwarding Rule Created")
def detect_mail_forwarding(event: dict, all_events: list[dict]) -> dict | None:
    """Detect creation of mailbox rules that forward to external domains."""
    if event.get("source") != "auditLog":
        return None
    activity = event.get("activity", "").lower()
    if "forward" in activity or "redirect" in activity or "rule" in activity:
        return {
            "detection_type": "mail_forwarding",
            "severity": "high",
            "title": f"Mail Forwarding Rule — {event.get('user','?')}",
            "description": f"{event.get('activity','')}: {', '.join(event.get('target_resources',[]))}",
            "user": event.get("user", ""),
            "timestamp": event.get("created_at", ""),
            "event_id": event.get("id", ""),
        }
    return None


# ═══════════════════════════════════════════════════════
#  Risk detection passthrough
# ═══════════════════════════════════════════════════════

@detection("high", "Entra ID Risk Detection")
def detect_entra_risk(event: dict, all_events: list[dict]) -> dict | None:
    """Pass through Entra ID risk detections as our own detections."""
    if event.get("source") != "riskDetection":
        return None
    risk_level = event.get("risk_level", "")
    if risk_level in ("high", "medium"):
        rtype = event.get("risk_type", "unknown")
        return {
            "detection_type": "entra_risk",
            "severity": "high" if risk_level == "high" else "medium",
            "title": f"Entra ID Risk: {rtype} — {event.get('user','?')}",
            "description": f"Risk type: {rtype}. Detail: {event.get('detail','')}",
            "user": event.get("user", ""),
            "timestamp": event.get("created_at", ""),
            "event_id": event.get("id", ""),
        }
    return None


# ═══════════════════════════════════════════════════════
#  Engine
# ═══════════════════════════════════════════════════════



@detection("high", "OAuth Application Consent")
def detect_oauth_consent(event: dict, all_events: list[dict]) -> dict | None:
    """Detect when a user consents to an OAuth application (potential rogue app)."""
    if event.get("source") != "auditLog":
        return None
    activity = event.get("activity", "").lower()
    if "consent" in activity or "oauth" in activity:
        user = event.get("user", "")
        targets = event.get("target_resources", [])
        return {
            "detection_type": "oauth_consent",
            "severity": "high",
            "title": f"OAuth Consent Granted — {user or 'unknown'}",
            "description": f"{event.get('activity','')}: {', '.join(targets)[:120]}",
            "user": user,
            "timestamp": event.get("created_at", ""),
            "event_id": event.get("id", ""),
        }
    return None


@detection("high", "User Security Info Reset")
def detect_security_info_reset(event: dict, all_events: list[dict]) -> dict | None:
    """Detect bulk security info registration (potential MFA reset by attacker)."""
    if event.get("source") != "auditLog":
        return None
    activity = event.get("activity", "").lower()
    if "registered security info" in activity or "started security info" in activity:
        user = event.get("user", "")
        if not user:
            return None
        # Check if user has multiple registrations in short time
        recent = [
            e for e in all_events[:200]
            if e.get("user") == user
            and e.get("source") == "auditLog"
            and ("security info" in (e.get("activity","") or "").lower())
            and e.get("id") != event.get("id")
        ]
        if len(recent) >= 3:
            return {
                "detection_type": "security_info_reset",
                "severity": "high",
                "title": f"Bulk Security Info Registration — {user}",
                "description": f"{len(recent)+1} security info registrations. Possible MFA reset attack.",
                "user": user,
                "timestamp": event.get("created_at", ""),
                "event_id": event.get("id", ""),
            }
    return None


@detection("high", "Account Disabled/Enabled")
def detect_account_status_change(event: dict, all_events: list[dict]) -> dict | None:
    """Detect account disable/enable events."""
    if event.get("source") != "auditLog":
        return None
    activity = event.get("activity", "").lower()
    if "disable account" in activity or "enable account" in activity:
        user = event.get("user", "")
        return {
            "detection_type": "account_status_change",
            "severity": "high",
            "title": f"Account {'Disabled' if 'disable' in activity else 'Enabled'} — {user or 'unknown'}",
            "description": f"{event.get('activity','')}",
            "user": user,
            "timestamp": event.get("created_at", ""),
            "event_id": event.get("id", ""),
        }
    return None

def _parse_ts(ts_str: str) -> datetime | None:
    """Parse ISO timestamp string to datetime."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


# ── Microsoft Defender events ─────────────────────────────────────────────
# Defender alerts/incidents arrive already classified, so the identity rules do
# not apply. They become cases directly, deduped by alert/incident id.

DEFENDER_SEVERITY = {"high": "high", "critical": "high", "medium": "medium",
                     "low": "low", "informational": "low", "unknown": "medium"}


@detection("high", "defender_event")
def detect_defender_event(event: dict, all_events: list[dict]) -> dict | None:
    """Turn a Defender alert/incident into a case-worthy detection."""
    source = event.get("source", "")
    if source not in ("defenderAlert", "defenderIncident", "mdeAlert"):
        return None
    severity = DEFENDER_SEVERITY.get((event.get("severity") or "unknown").lower(), "medium")
    if severity == "low":
        return None
    status = (event.get("status") or "").lower()
    if status in ("resolved", "dismissed", "redirected", "falsepositive"):
        return None
    label = {"defenderAlert": "Defender alert", "defenderIncident": "Defender incident",
             "mdeAlert": "Defender for Endpoint alert"}[source]
    detail = []
    for key in ("service_source", "category", "device", "mitre", "alert_count"):
        val = event.get(key)
        if val:
            detail.append(f"{key.replace('_', ' ')}: {', '.join(val) if isinstance(val, list) else val}")
    return {
        "detection_type": {"defenderAlert": "defender_alert", "defenderIncident": "defender_incident",
                           "mdeAlert": "mde_alert"}[source],
        "dedup_field": "event_id",
        "severity": severity,
        "title": f"{label}: {event.get('title', '').strip()[:120]}" or label,
        "description": (event.get("description") or "")[:600]
                       + ("\n" + "\n".join(detail) if detail else ""),
        "user": event.get("user", ""),
        "event_id": event.get("id", ""),
    }


def run_detections(events: list[dict]) -> list[dict]:
    """Run all detection rules against the latest events.
    Returns list of detection results (alerts/cases to create).
    """
    alerts = []
    for rule in DETECTIONS:
        for event in events[:500]:  # Check latest 500 events
            try:
                result = rule["func"](event, events)
                if result:
                    result["detection_name"] = rule["name"]
                    result["severity"] = result.get("severity", rule["severity"])
                    alerts.append(result)
            except Exception as e:
                logger.warning("Detection rule '%s' failed: %s", rule["name"], e)
    return alerts
