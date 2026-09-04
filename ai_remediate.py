"""Remediation executor — carries out response plan actions for approved cases."""
import json
import logging
import os
import subprocess
import requests
from datetime import datetime, timezone

logger = logging.getLogger("ai_remediate")

WAZUH_API_BASE = os.getenv("WAZUH_SOC_API_BASE", "http://208.87.135.185:5000/api")
WAZUH_USER = os.getenv("WAZUH_SOC_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_SOC_PASS", "admin123")

_wazuh_token = {"value": ""}
BASE_DIR = os.path.dirname(__file__)

# ── Action tier classification (Phase 2 — AI-Everywhere engine) ────────────
# Tier 1 = reversible / contained / informational → auto-executable by the
#          AI autopilot at case creation, with full audit trail.
# Tier 2 = major change (hardware/software/tenant/network-wide) → human-gated.
# The user's line: humans stay in the loop for alerts that cause major change.

ACTION_TIERS: dict[str, int] = {
    # Tier 1 — reversible / contained / informational
    "notify": 1, "notify_soc": 1, "alert": 1,
    "add_watchlist": 1, "watchlist": 1, "ioc": 1,
    "suppress": 1, "suppress_rule": 1, "mute": 1,
    "ping": 1, "ping_device": 1, "check": 1,
    "investigate": 1, "review": 1, "escalate": 1,
    # Tier 2 — major change
    "block": 2, "block_ip": 2,
    "isolate": 2, "isolate_agent": 2, "quarantine": 2, "release": 2,
    "revoke": 2, "revoke_session": 2, "revoke_token": 2,
    "reset_password": 2, "disable_account": 2, "disable_user": 2,
    "require_mfa": 2, "disable_mfa": 2, "enforce_mfa": 2,
    "firewall_change": 2, "geo_block": 2, "offboard": 2, "offboard_domain": 2,
    "delete": 2, "delete_data": 2, "remove": 2, "uninstall": 2,
    "patch": 2, "update": 2, "remediate": 2, "reboot": 2, "firmware": 2,
}
DEFAULT_ACTION_TIER = 2  # unknown actions default to human-gated

# Human-readable rollback guidance, surfaced when a case executes.
ROLLBACK_NOTES: dict[str, str] = {
    "block_ip": "Remove the iptables INPUT DROP rule for the address.",
    "block": "Remove the iptables INPUT DROP rule for the address.",
    "isolate": "Issue EDR release for the affected agent(s).",
    "isolate_agent": "Issue EDR release for the affected agent(s).",
    "quarantine": "Issue EDR release for the affected agent(s).",
    "release": "Re-apply isolation if the host is still suspect.",
    "suppress": "Remove the source entry from the soc_suppressions CDB list.",
    "suppress_rule": "Remove the source entry from the soc_suppressions CDB list.",
    "mute": "Remove the source entry from the soc_suppressions CDB list.",
    "add_watchlist": "Remove the IOC entry from watchlist.json.",
    "watchlist": "Remove the IOC entry from watchlist.json.",
    "ioc": "Remove the IOC entry from watchlist.json.",
    "revoke_session": "Re-issue the sign-in session via Microsoft 365 admin.",
    "revoke_token": "Re-issue the token via Microsoft 365 admin.",
    "reset_password": "Inform the user of the new credential; audit the reset.",
    "disable_account": "Re-enable the account from Microsoft 365 admin.",
    "disable_mfa": "Re-enable MFA requirements from Microsoft 365 admin.",
    "require_mfa": "Roll back the MFA requirement if business impact is confirmed.",
    "enforce_mfa": "Roll back the MFA requirement if business impact is confirmed.",
}
GENERIC_ROLLBACK = "Reversible via the SOC console or audit trail; verify after execution."


def _normalize_action(action) -> tuple[str, str, dict]:
    """Normalize a plan action (str or dict) → (action_type, target, params)."""
    if isinstance(action, str):
        return action.lower().replace(" ", "_"), "", {}
    action_type = (action.get("type", "") or "").lower().replace(" ", "_")
    target = action.get("target", action.get("value", ""))
    return action_type, target, action


def action_tier(action) -> int:
    """Tier for a raw plan action. Unknown types are conservative (Tier 2),
    except common informational step prefixes which are Tier 1."""
    action_type, _, _ = _normalize_action(action)
    tier = ACTION_TIERS.get(action_type)
    if tier is not None:
        return tier
    if action_type.startswith((
        "review_", "verify_", "check_", "log_",
        "investigate_", "alert_", "escalate_", "notify_",
    )):
        return 1
    return DEFAULT_ACTION_TIER


def _extract_plan(case: dict) -> list:
    """Pull the action list out of a case (handles str/list/dict encodings)."""
    plan = case.get("response_plan", [])
    if isinstance(plan, str):
        try:
            plan = json.loads(plan)
        except (json.JSONDecodeError, TypeError):
            plan = []
    if isinstance(plan, dict):
        plan = plan.get("actions", plan.get("response_plan", []))
    return plan if isinstance(plan, list) else []


def classify_case(case: dict) -> dict:
    """Split a case's response plan into tier1 (auto) / tier2 (human-gated)."""
    tier1, tier2 = [], []
    for action in _extract_plan(case):
        (tier1 if action_tier(action) == 1 else tier2).append(action)
    return {"tier1": tier1, "tier2": tier2}


def rollback_notes(action) -> str:
    """Human-readable rollback guidance for a plan action."""
    action_type, _, _ = _normalize_action(action)
    return ROLLBACK_NOTES.get(action_type, GENERIC_ROLLBACK)


def _wazuh_login() -> str:
    if _wazuh_token["value"]:
        return _wazuh_token["value"]
    try:
        r = requests.post(
            f"{WAZUH_API_BASE}/auth/login",
            json={"username": WAZUH_USER, "password": WAZUH_PASS},
            timeout=10,
        )
        if r.ok:
            _wazuh_token["value"] = r.json().get("token", "")
            return _wazuh_token["value"]
    except Exception as e:
        logger.error("Wazuh login failed: %s", e)
    return ""


def ping_device(ip: str) -> dict:
    """Check device reachability via ping."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "3", ip],
            capture_output=True, timeout=10, text=True,
        )
        alive = r.returncode == 0
        rtt = None
        if alive and "time=" in r.stdout:
            try:
                rtt = float(r.stdout.split("time=")[1].split(" ")[0])
            except (ValueError, IndexError):
                pass
        return {"success": True, "action": "ping", "target": ip, "alive": alive, "rtt_ms": rtt}
    except subprocess.TimeoutExpired:
        return {"success": True, "action": "ping", "target": ip, "alive": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "action": "ping", "error": str(e)}


def block_ip(address: str) -> dict:
    """Add iptables rule to drop traffic from source IP."""
    try:
        r = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", address, "-j", "DROP"],
            capture_output=True, timeout=10, text=True,
        )
        if r.returncode == 0:
            logger.info("Blocked IP %s via iptables", address)
            return {"success": True, "action": "block_ip", "target": address}
        return {"success": False, "action": "block_ip", "error": r.stderr.strip()}
    except FileNotFoundError:
        return {"success": False, "action": "block_ip", "error": "iptables not available"}
    except Exception as e:
        return {"success": False, "action": "block_ip", "error": str(e)}


def suppress_rule(rule_id: int, source: str, alert_type: str = "") -> dict:
    """Suppress a Wazuh rule for a specific source via CDB list."""
    token = _wazuh_login()
    if not token:
        return {"success": False, "action": "suppress_rule", "error": "no auth"}
    try:
        entry = f"{source}:{alert_type}" if alert_type else source
        resp = requests.put(
            f"{WAZUH_API_BASE}/lists",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "soc_suppressions",
                "content": {entry: "suppressed"},
            },
            timeout=15,
        )
        if resp.ok:
            logger.info("Suppressed rule %d for %s", rule_id, source)
            return {"success": True, "action": "suppress_rule", "target": entry}
        return {"success": False, "action": "suppress_rule", "error": resp.text[:200]}
    except Exception as e:
        return {"success": False, "action": "suppress_rule", "error": str(e)}


def notify_soc(message: str, level: str = "info") -> dict:
    """Send notification via Telegram (plain text, no markdown)."""
    try:
        from soc_agent import tg_send
        ok = tg_send(f"[{level.upper()}] {message}", parse_mode="")
        if ok:
            logger.info("Telegram notification sent: %s", message[:80])
            return {"success": True, "action": "notify", "target": "telegram", "message": message[:80]}
        return {"success": False, "action": "notify", "error": "tg_send returned False"}
    except Exception as e:
        logger.warning("Telegram notify failed: %s", e)
    return {"success": False, "action": "notify", "error": str(e)}


def add_watchlist(ioc: str, ioc_type: str = "ip") -> dict:
    """Add IOC to local watchlist file."""
    watch_file = os.path.join(BASE_DIR, "watchlist.json")
    try:
        entries = []
        if os.path.exists(watch_file):
            with open(watch_file) as f:
                entries = json.load(f)
        entries.append({
            "value": ioc,
            "type": ioc_type,
            "added": datetime.now(timezone.utc).isoformat(),
            "source": "ai_remediation",
        })
        with open(watch_file, "w") as f:
            json.dump(entries, f, indent=2)
        logger.info("Added %s (%s) to watchlist", ioc, ioc_type)
        return {"success": True, "action": "add_watchlist", "target": ioc}
    except Exception as e:
        return {"success": False, "action": "add_watchlist", "error": str(e)}


def execute_case(case: dict, tier: int | None = None, dry_run: bool = False) -> list[dict]:
    """Execute the response plan for a case.

    Args:
        case:    the case dict (reads `response_plan`, `severity`, `title`, `id`).
        tier:    None → run the full plan (legacy behavior);
                 1 → run only reversible Tier-1 actions;
                 2 → run only human-gated Tier-2 actions.
        dry_run: if True, returns a plan preview with rollback guidance
                 instead of executing anything.

    Returns a list of result dicts.
    """
    results = []
    plan = _extract_plan(case)
    level = case.get("severity", "low")
    title = case.get("title", "")
    case_id = case.get("id", "?")

    if tier == 1:
        plan = [a for a in plan if action_tier(a) == 1]
    elif tier == 2:
        plan = [a for a in plan if action_tier(a) == 2]

    if not plan:
        if tier is None:
            # If no plan, notify as default
            results.append(notify_soc(f"Case {case_id}: {title} — executed (no specific actions)", level))
        return results

    for action in plan:
        if isinstance(action, str):
            action_type = action.lower().replace(" ", "_")
            target = ""
        else:
            action_type = (action.get("type", "") or "").lower().replace(" ", "_")
            target = action.get("target", action.get("value", ""))

        if dry_run:
            results.append({
                "action": action_type,
                "target": target,
                "tier": action_tier(action),
                "dry_run": True,
                "rollback": rollback_notes(action),
            })
            continue

        if action_type in ("block_ip", "block") and target:
            results.append(block_ip(target))
        elif action_type in ("ping", "ping_device", "check") and target:
            results.append(ping_device(target))
        elif action_type in ("suppress", "suppress_rule", "mute"):
            results.append(suppress_rule(
                case.get("rule_id", 0),
                target or case.get("source", ""),
                action.get("alert_type", "") if not isinstance(action, str) else "",
            ))
        elif action_type in ("notify", "notify_soc", "alert"):
            msg = action.get("rationale", "") if not isinstance(action, str) else f"Case: {title}"
            results.append(notify_soc(f"Case {case_id}: {title} — {msg}", level))
        elif action_type in ("watchlist", "ioc", "add_to_watchlist", "add_watchlist") and target:
            results.append(add_watchlist(target))
        elif action_type in ("investigate", "review", "escalate"):
            results.append(notify_soc(
                f"Case {case_id}: {title} — requires investigation", "high"))
        elif target:
            # Unknown action type with a target — never execute silently.
            # Surface it for human review instead (was: generic ping).
            results.append({"success": False, "action": action_type,
                            "target": target,
                            "error": "unknown action — skipped, human review required"})
        else:
            results.append(notify_soc(
                f"Case {case_id}: {title} — action: {action_type}", "info"))

    return results
