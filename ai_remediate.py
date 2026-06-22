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


def execute_case(case: dict) -> list[dict]:
    """Execute the full response plan for a case.

    Reads the response_plan from the case and runs each actionable step.
    Returns a list of result dicts.
    """
    results = []
    plan = case.get("response_plan", [])
    level = case.get("severity", "low")
    title = case.get("title", "")
    case_id = case.get("id", "?")

    if isinstance(plan, str):
        try:
            plan = json.loads(plan)
        except (json.JSONDecodeError, TypeError):
            plan = []
    if isinstance(plan, dict):
        plan = plan.get("actions", plan.get("response_plan", []))

    if not plan:
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
        elif action_type in ("watchlist", "ioc", "add_to_watchlist") and target:
            results.append(add_watchlist(target))
        elif action_type in ("investigate", "review", "escalate"):
            results.append(notify_soc(
                f"Case {case_id}: {title} — requires investigation", "high"))
        elif target:
            # Unknown action type with a target — try ping as generic check
            results.append(ping_device(target))
        else:
            results.append(notify_soc(
                f"Case {case_id}: {title} — action: {action_type}", "info"))

    return results
