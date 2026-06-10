"""
SOC Auto-Triage Agent + Telegram Bot

Monitors Wazuh SOC alerts, auto-resolves false positives, creates
autopilot cases, and sends Telegram notifications.

Runs as a background daemon thread inside app.py.

Environment variables:
  TELEGRAM_BOT_TOKEN=<token>          # BotFather token
  TELEGRAM_CHAT_ID=<chat_id>          # Target chat/group ID
  TELEGRAM_ENABLED=true               # Enable Telegram integration
  TRIAGE_INTERVAL_SECONDS=300         # Check interval (default 5 min)
"""

import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("soc_agent")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "false").strip().lower() in ("true", "1", "yes")
TRIAGE_INTERVAL = int(os.getenv("TRIAGE_INTERVAL_SECONDS", "300"))

API_BASE = "http://127.0.0.1:8095"
API_KEY = os.getenv("MISSION_API_KEY", "mission-test-key-123")

# Direct Supabase access (falls back to API if unavailable)
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
_SUPABASE_HEADERS = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"} if SUPABASE_KEY else {}

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"


# ── Telegram ─────────────────────────────────────────────────────────────

def tg_send(text: str, parse_mode: str = "Markdown") -> bool:
    """Send a message to the configured Telegram chat."""
    if not TELEGRAM_ENABLED or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        resp = requests.post(
            f"{TELEGRAM_API}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": parse_mode},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning("Telegram send failed: %s", resp.text[:200])
        return resp.status_code == 200
    except Exception as exc:
        logger.warning("Telegram send error: %s", exc)
        return False


def tg_send_alert(alert: Dict[str, Any], site_name: str = "") -> bool:
    """Send a formatted alert message to Telegram."""
    sev = (alert.get("severity") or "low").upper()
    emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "ℹ️"}.get(sev, "🔹")
    title = alert.get("title", "Unknown alert")
    msg = alert.get("message", "")
    alert_type = alert.get("alert_type", "")
    count = alert.get("count", 1)

    text = (
        f"{emoji} *{sev} Alert*{' (x' + str(count) + ')' if count > 1 else ''}\n"
        f"*{title}*\n"
        f"`{alert_type}`"
    )
    if site_name:
        text += f"\n📍 {site_name}"
    if msg:
        text += f"\n_{msg[:200]}_"
    return tg_send(text)


def tg_send_summary(stats: Dict[str, Any]) -> bool:
    """Send a periodic SOC summary."""
    text = (
        f"📊 *SOC Summary* — {datetime.now(timezone.utc).strftime('%H:%M UTC')}\n"
        f"Open alerts: {stats.get('total_alerts', 0)}\n"
        f"🔴 Critical: {stats.get('critical', 0)}\n"
        f"⚠️ High: {stats.get('high', 0)}\n"
        f"🔶 Medium: {stats.get('medium', 0)}\n"
        f"🔹 Low: {stats.get('low', 0)}\n"
        f"Autopilot cases: {stats.get('cases', 0)}"
    )
    return tg_send(text)


# ── Telegram Command Polling ────────────────────────────────────────────

_LAST_UPDATE_ID = 0
_ESCALATED_ALERTS = set()  # alert IDs that have been escalated
ESCALATION_THRESHOLD_MINUTES = int(os.getenv("ESCALATION_THRESHOLD_MINUTES", "30"))
SUMMARY_COOLDOWN_MINUTES = int(os.getenv("SUMMARY_COOLDOWN_MINUTES", "30"))
SUMMARY_STATS_FILE = os.path.join(os.path.dirname(__file__), "summary_stats.json")


def _handle_command(chat_id: str, cmd: str, args: str) -> str:
    """Process a Telegram command and return the response text."""
    cmd = cmd.lower()

    if cmd == "/start":
        return (
            "🤖 *SOC Agent Online*\n\n"
            "I monitor the Wazuh SOC and can answer queries.\n"
            "Send /help for available commands."
        )

    if cmd == "/help":
        return (
            "📋 *Available Commands*\n\n"
            "/status — SOC summary (alerts, cases, devices)\n"
            "/alerts — recent open alerts\n"
            "/cases — active autopilot cases\n"
            "/ack {id} — acknowledge an alert by ID\n"
            "/resolve {id} — resolve an alert by ID\n"
            "/help — this message"
        )

    if cmd == "/status":
        stats = _get_stats()
        return (
            f"📊 *SOC Status*\n"
            f"Open alerts: {stats.get('total_alerts', 0)}\n"
            f"🔴 Critical: {stats.get('critical', 0)}\n"
            f"⚠️ High: {stats.get('high', 0)}\n"
            f"🔶 Medium: {stats.get('medium', 0)}\n"
            f"🔹 Low: {stats.get('low', 0)}\n"
            f"📋 Cases: {stats.get('cases', 0)}"
        )

    if cmd == "/alerts":
        data = _api_get("/api/v1/alert-summary", params={"_": int(time.time())})
        if not data or not isinstance(data, dict):
            return "❌ Could not fetch alerts."
        summary = data.get("summary", {})
        total = summary.get("total_alerts", 0)
        if total == 0:
            return "✅ No open alerts. All clear."
        sev = summary.get("severity_counts", {})
        lines = [f"🚨 *Open Alerts* ({total})", f"🔴 Critical: {sev.get('CRITICAL', 0)}", f"⚠️ High: {sev.get('HIGH', 0)}", f"🔶 Medium: {sev.get('MEDIUM', 0)}", f"🔹 Low: {sev.get('LOW', 0)}"]

        # Top sites with most alerts
        top_sites = data.get("top_sites", [])
        if top_sites:
            lines.append("\n📍 *Top Sites*")
            for s in top_sites[:3]:
                site = s.get("site", {})
                name = site.get("site_name") or site.get("site_code") or "Unknown"
                total_s = s.get("total", 0)
                lines.append(f"• {name}: {total_s} alerts")

        return "\n".join(lines)

    if cmd == "/cases":
        data = _api_get("/wazuh-api/autopilot/cases")
        if not data or not isinstance(data, dict):
            return "❌ Could not fetch cases."
        items = data.get("affected_items", [])
        if not items:
            return "📋 No active autopilot cases."
        lines = [f"📋 *Autopilot Cases* ({len(items)})"]
        for c in items[:5]:
            status = c.get("status", "open")
            emoji = {"awaiting_approval": "⏳", "approved": "✅", "in_progress": "🔄", "rejected": "❌", "resolved": "✅"}.get(status, "🔹")
            sev = c.get("severity", "low")
            lines.append(f"{emoji} #{c.get('id','?')} [{sev}] {c.get('title','')[:50]}")
        if len(items) > 5:
            lines.append(f"\n... and {len(items) - 5} more")
        return "\n".join(lines)

    if cmd == "/ack":
        if not args:
            return "❌ Usage: /ack {alert_id}\nExample: `/ack a1b2c3d4`"
        alert_id = args.strip()
        return _update_alert_status(alert_id, "ACKNOWLEDGED")

    if cmd == "/resolve":
        if not args:
            return "❌ Usage: /resolve {alert_id}\nExample: `/resolve a1b2c3d4`"
        alert_id = args.strip()
        return _update_alert_status(alert_id, "RESOLVED")

    return f"❌ Unknown command: {cmd}\nSend /help for available commands."


def _update_alert_status(alert_id: str, new_status: str) -> str:
    """Update an alert's status via Supabase REST API."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return "❌ Supabase not configured — cannot update alerts."
    if new_status not in ("ACKNOWLEDGED", "RESOLVED"):
        return f"❌ Invalid status: {new_status}"
    try:
        url = f"{SUPABASE_URL}/rest/v1/mc_alerts"
        params = {"id": f"eq.{alert_id}"}
        payload = {
            "status": new_status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if new_status == "ACKNOWLEDGED":
            payload["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
            payload["acknowledged_by"] = "telegram_bot"
        elif new_status == "RESOLVED":
            payload["resolved_at"] = datetime.now(timezone.utc).isoformat()
            payload["resolved_by"] = "telegram_bot"
        resp = requests.patch(url, headers=_SUPABASE_HEADERS, params=params, json=payload, timeout=10)
        if resp.status_code == 200:
            emoji = "✅" if new_status == "RESOLVED" else "👁️"
            return f"{emoji} Alert `{alert_id}` {new_status.lower()}."
        elif resp.status_code == 404:
            return f"❌ Alert `{alert_id}` not found."
        else:
            return f"❌ Failed to update alert `{alert_id}`: {resp.status_code} {resp.text[:100]}"
    except Exception as exc:
        return f"❌ Error updating alert: {exc}"


def _poll_telegram():
    """Long-poll Telegram for incoming commands and respond."""
    global _LAST_UPDATE_ID
    offset = _LAST_UPDATE_ID
    url = f"{TELEGRAM_API}/getUpdates"
    params = {"offset": offset + 1, "timeout": 30, "allowed_updates": ["message"]}

    try:
        resp = requests.get(url, params=params, timeout=35)
        if resp.status_code != 200:
            return
        data = resp.json()
        if not data.get("ok"):
            return
        for update in data.get("result", []):
            update_id = update.get("update_id", 0)
            if update_id > _LAST_UPDATE_ID:
                _LAST_UPDATE_ID = update_id
            msg = update.get("message", {})
            chat = msg.get("chat", {})
            chat_id = str(chat.get("id", ""))
            text = (msg.get("text") or "").strip()
            if not chat_id or not text:
                continue
            if not text.startswith("/"):
                continue
            parts = text.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            response = _handle_command(chat_id, cmd, args)

            # Send reply
            try:
                requests.post(
                    f"{TELEGRAM_API}/sendMessage",
                    json={"chat_id": chat_id, "text": response, "parse_mode": "Markdown"},
                    timeout=10,
                )
            except Exception as exc:
                logger.warning("Telegram reply error: %s", exc)
    except requests.Timeout:
        pass  # Long poll timeout is normal
    except Exception as exc:
        logger.warning("Telegram poll error: %s", exc)


# ── Auto-Triage Engine ──────────────────────────────────────────────────

def _supabase_get(table: str, params: dict = None) -> Optional[list]:
    """Query Supabase directly (bypasses the backend API)."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        resp = requests.get(url, headers=_SUPABASE_HEADERS, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as exc:
        logger.debug("Supabase GET %s failed: %s", table, exc)
        return None


def _get_alerts_direct(status: str = "OPEN,ACKNOWLEDGED", limit: int = 100) -> list:
    """Fetch alerts directly from Supabase with enriched data."""
    alerts = _supabase_get("mc_alerts", {
        "status": f"in.({status})",
        "select": "id,site_id,device_id,alert_type,severity,status,title,message,first_seen_at,last_seen_at,count,fingerprint",
        "order": "last_seen_at.desc",
        "limit": str(limit),
    })
    if alerts is None:
        return []
    return alerts


def _get_sites_direct() -> dict:
    """Fetch sites from Supabase."""
    sites = _supabase_get("mc_sites", {"select": "id,site_code,site_name", "limit": "500"})
    if sites is None:
        return {}
    return {str(s["id"]): s for s in sites if s.get("id")}


def _get_device_direct(device_id: str) -> Optional[dict]:
    """Fetch a single device from Supabase."""
    devices = _supabase_get("mc_network_devices", {"id": f"eq.{device_id}", "select": "id,ip_address,hostname,friendly_name,vendor,device_type,status", "limit": "1"})
    if devices:
        return devices[0]
    return None


def _get_stats() -> Dict[str, Any]:
    """Gather SOC stats — tries Supabase direct first, falls back to API."""
    result = {"total_alerts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "cases": 0}

    # Try direct Supabase first
    alerts = _get_alerts_direct(limit=200)
    if alerts:
        result["total_alerts"] = len(alerts)
        for a in alerts:
            sev = (a.get("severity") or "low").upper()
            if sev == "CRITICAL":
                result["critical"] += 1
            elif sev == "HIGH":
                result["high"] += 1
            elif sev == "MEDIUM":
                result["medium"] += 1
            elif sev == "LOW":
                result["low"] += 1
    else:
        # Fallback to API
        stats = _api_get("/wazuh-api/autopilot/stats")
        if stats:
            result["critical"] = stats.get("critical", 0)
            result["high"] = stats.get("high", 0)
            result["medium"] = stats.get("medium", 0)
            result["low"] = stats.get("low", 0)

    # Get case count from local file
    import json as _json
    cases_file = os.path.join(os.path.dirname(__file__), "autopilot_cases.json")
    if os.path.exists(cases_file):
        try:
            result["cases"] = len(_json.load(open(cases_file)))
        except Exception:
            pass

    return result


def _api_get(path: str, params: dict = None) -> Optional[Dict]:
    """Make an authenticated API call to the local backend."""
    try:
        resp = requests.get(
            f"{API_BASE}{path}",
            params=params,
            headers={"x-api-key": API_KEY},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        logger.debug("API GET %s returned %s", path, resp.status_code)
        return None
    except Exception as exc:
        logger.debug("API GET %s failed: %s", path, exc)
        return None


def _api_post(path: str, data: dict = None) -> bool:
    """Make an authenticated POST to the local backend."""
    try:
        resp = requests.post(
            f"{API_BASE}{path}",
            json=data or {},
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as exc:
        logger.debug("API POST %s failed: %s", path, exc)
        return False


def _triage_cycle() -> Dict[str, Any]:
    """
    One triage cycle:
    1. Check for existing autopilot cases that need attention
    2. Trigger autopilot scan (creates cases from alert clusters)
    3. Escalate critical alerts that have persisted beyond threshold
    4. Send multi-channel notification (Telegram + Slack/Teams/Email)
    5. Send Telegram summary if counts changed
    """
    global _ESCALATED_ALERTS
    actions = []
    now = datetime.now(timezone.utc)

    # Step 1: Check for alerts needing escalation (direct Supabase)
    try:
        sites_map = _get_sites_direct()
        for a in _get_alerts_direct(status="OPEN", limit=50):
            alert_id = str(a.get("id", ""))
            if not alert_id or alert_id in _ESCALATED_ALERTS:
                continue
            sev = (a.get("severity") or "low").upper()
            if sev != "CRITICAL":
                continue
            first_seen = a.get("first_seen_at", "")
            if not first_seen:
                continue
            try:
                seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                elapsed_min = (now - seen_dt).total_seconds() / 60
            except Exception:
                continue
            if elapsed_min >= ESCALATION_THRESHOLD_MINUTES:
                    _ESCALATED_ALERTS.add(alert_id)
                    title = a.get("title", "Unknown")
                    msg = a.get("message", "")
                    alert_type = a.get("alert_type", "")
                    site = sites_map.get(str(a.get("site_id", "")), {}).get("site_name", "")
                    device = _get_device_direct(str(a.get("device_id", ""))) if a.get("device_id") else None
                    device_ip = device.get("ip_address", "") if device else ""
                    tg_send(
                        f"🚨 *ESCALATION — Critical Alert Persisting*\n"
                        f"*{title}*\n"
                        f"Type: `{alert_type}`\n"
                        f"Open for: {int(elapsed_min)} minutes\n"
                        f"{'📍 ' + site if site else ''}\n"
                        f"{'💻 ' + device_ip if device_ip else ''}\n"
                        f"_{msg[:200]}_\n\n"
                        f"⚠️ This alert exceeds the {ESCALATION_THRESHOLD_MINUTES}min escalation threshold."
                    )
                    actions.append(("escalated_alert", alert_id))
    except Exception as exc:
        logger.debug("Escalation check error: %s", exc)

    # Step 2: Send multi-channel alert via Slack/Teams/Email (notify.py)
    try:
        sys.path.insert(0, "/home/aiagent/mission-control-site")
        from notify import notify_alert as _notify_multi, should_notify as _should_notify_multi
        alert_stats = _get_stats()
        if alert_stats.get("critical", 0) > 0 or alert_stats.get("high", 0) > 0:
            summary_alert = {
                "severity": "CRITICAL" if alert_stats.get("critical", 0) > 0 else "HIGH",
                "title": f"SOC Alert Summary — {alert_stats.get('total_alerts', 0)} open alerts",
                "message": f"Critical: {alert_stats.get('critical', 0)}, High: {alert_stats.get('high', 0)}, Medium: {alert_stats.get('medium', 0)}, Low: {alert_stats.get('low', 0)}",
                "alert_type": "SOC_AGENT_SUMMARY",
                "count": 1,
                "first_seen_at": datetime.now(timezone.utc).isoformat(),
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            }
            if _should_notify_multi(summary_alert):
                _notify_multi(summary_alert, site_name="Mission Control", device_info="")
                actions.append(("multi_channel_notify", "sent"))
    except ImportError:
        logger.debug("notify.py not available — multi-channel notification skipped")
    except Exception as exc:
        logger.debug("Multi-channel notify error: %s", exc)

    # Step 3: Trigger autopilot scan to find new alert clusters
    scan_ok = _api_post("/wazuh-api/autopilot/scan")
    actions.append(("autopilot_scan", "ok" if scan_ok else "failed"))

    # Step 3: Get current stats
    stats = _get_stats()
    actions.append(("stats", stats))

    # Step 4: Send Telegram summary only if counts changed + cooldown elapsed
    import json as _json
    _last_sent = {"stats": {}, "time": 0}
    if os.path.exists(SUMMARY_STATS_FILE):
        try:
            _last_sent = _json.load(open(SUMMARY_STATS_FILE))
        except Exception:
            pass
    _last_time = _last_sent.get("time", 0)
    _elapsed = (datetime.now(timezone.utc).timestamp() - _last_time) / 60 if _last_time else 999
    _changed = (
        stats.get("total_alerts") != _last_sent["stats"].get("total_alerts") or
        stats.get("critical") != _last_sent["stats"].get("critical") or
        stats.get("high") != _last_sent["stats"].get("high") or
        stats.get("medium") != _last_sent["stats"].get("medium") or
        stats.get("low") != _last_sent["stats"].get("low")
    )
    if TELEGRAM_ENABLED and stats.get("total_alerts", 0) > 0 and _changed and _elapsed >= SUMMARY_COOLDOWN_MINUTES:
        tg_send_summary(stats)
        actions.append(("telegram_summary", "sent"))
        _json.dump({"stats": stats, "time": datetime.now(timezone.utc).timestamp()}, open(SUMMARY_STATS_FILE, "w"))

    return {"actions": actions, "stats": stats, "time": datetime.now(timezone.utc).isoformat()}


def run_triage_cycle() -> Dict[str, Any]:
    """Run a single triage cycle (can be called from API endpoint too)."""
    try:
        return _triage_cycle()
    except Exception as exc:
        logger.error("Triage cycle failed: %s", exc)
        return {"error": str(exc)}


# ── Background Daemon ────────────────────────────────────────────────────

DIGEST_HOUR = int(os.getenv("DIGEST_HOUR", "8"))
DIGEST_FILE = os.path.join(os.path.dirname(__file__), "digest_snapshot.json")


def _last_digest_date() -> str:
    import json as _json
    if os.path.exists(DIGEST_FILE):
        try:
            return _json.load(open(DIGEST_FILE)).get("date", "")
        except Exception:
            return ""
    return ""


def _save_digest_snapshot(stats: dict) -> None:
    import json as _json
    _json.dump({"date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "stats": stats, "time": datetime.now(timezone.utc).isoformat()}, open(DIGEST_FILE, "w"))


def _send_digest() -> bool:
    """Generate and send the daily SOC digest via Telegram."""
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    # Gather current stats
    stats = _get_stats()
    cases_data = _api_get("/wazuh-api/autopilot/cases")
    active_cases = len(cases_data.get("affected_items", [])) if cases_data else 0

    # Compare with previous snapshot
    prev = _last_digest_date()
    if prev == today:
        logger.debug("Digest already sent today")
        return False

    # Build digest
    total = stats.get("total_alerts", 0)
    critical = stats.get("critical", 0)
    high = stats.get("high", 0)
    medium = stats.get("medium", 0)

    # Health assessment
    if critical > 0:
        health = "🔴 Needs attention — critical alerts active"
    elif high > 0:
        health = "⚠️ Monitor — high-severity alerts present"
    elif total == 0:
        health = "✅ All clear — no open alerts"
    else:
        health = "🟡 Routine — low/medium alerts only"

    # Format
    lines = [
        f"📋 *Daily SOC Digest* — {today}",
        "",
        f"*Alert Overview*",
        f"🔴 Critical: {critical}",
        f"⚠️ High: {high}",
        f"🔶 Medium: {medium}",
        f"🔹 Low: {stats.get('low', 0)}",
        f"**Total: {total}**",
        "",
        f"*Autopilot*",
        f"📋 Active cases: {active_cases}",
        "",
        f"*Assessment*",
        health,
        "",
        f"🔄 Next digest: tomorrow ~{DIGEST_HOUR}:00 UTC",
    ]
    ok = tg_send("\n".join(lines))

    if ok:
        _save_digest_snapshot(stats)
        logger.info("Daily digest sent for %s", today)

    return ok


def start_daemon() -> threading.Thread:
    """Start the SOC agent daemon + Telegram poller + digest scheduler."""
    def _loop():
        logger.info("SOC Agent daemon started (interval=%ds)", TRIAGE_INTERVAL)
        while True:
            try:
                result = _triage_cycle()
                alerts = result.get("stats", {}).get("total_alerts", 0)
                logger.debug("Triage cycle complete: %d alerts, %d actions", alerts, len(result.get("actions", [])))
            except Exception as exc:
                logger.error("Triage daemon error: %s", exc)
            time.sleep(TRIAGE_INTERVAL)

    def _tg_poll_loop():
        if not TELEGRAM_ENABLED or not TELEGRAM_BOT_TOKEN:
            return
        logger.info("Telegram command poller started")
        while True:
            try:
                _poll_telegram()
            except Exception as exc:
                logger.debug("Telegram poll cycle error: %s", exc)
            time.sleep(3)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

    tg_thread = threading.Thread(target=_tg_poll_loop, daemon=True)
    tg_thread.start()

    def _digest_loop():
        if not TELEGRAM_ENABLED:
            return
        logger.info("Digest scheduler started (target hour=%d UTC)", DIGEST_HOUR)
        while True:
            try:
                now = datetime.now(timezone.utc)
                if now.hour == DIGEST_HOUR and now.minute < 5:
                    _send_digest()
                    # Wait until past the window to avoid re-sending
                    time.sleep(360)
            except Exception as exc:
                logger.error("Digest scheduler error: %s", exc)
            time.sleep(60)

    digest_thread = threading.Thread(target=_digest_loop, daemon=True)
    digest_thread.start()

    return thread


def send_test_notification() -> Dict[str, Any]:
    """Send a test Telegram message."""
    ok = tg_send(
        f"🧪 *SOC Agent Test*\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Server: Mission Control\n"
        f"Status: Online"
    )
    return {"success": ok, "channel": "telegram"}
