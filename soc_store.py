"""SOC data store — SQLite backing for the SOC API.

Single database file (soc.db) beside this module. Thread-safe via
check_same_thread=False + a per-write lock (FastAPI runs sync handlers
in a threadpool).

Tables:
  agents          — endpoint inventory (from agent telemetry / poll / WS)
  events          — SIEM events (agent-forwarded + ingested)
  alerts          — security alerts (from rules engine / AI triage)
  queue           — human SOC review queue (assignment, SLA, notes)
  itdr_events     — identity events (Graph API poller)
  itdr_cases      — ITDR incident cases
  fim_events      — file integrity monitoring events
  vuln_findings   — vulnerability findings (agents / package scans)
  rules           — detection rules
  playbooks       — automation playbooks
  playbook_audit  — playbook execution audit trail
  reports         — generated reports
  external_tokens — API tokens (VT, OTX etc.)
  settings        — key/value settings
  agent_commands  — command outbox for agents (WS/poll)
"""

import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc.db")

_lock = threading.Lock()
_conn = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_id(prefix: str = "soc") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    platform TEXT,
    version TEXT,
    ip TEXT,
    last_seen TEXT,
    status TEXT DEFAULT 'offline',
    telemetry TEXT DEFAULT '{}',
    first_seen TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts TEXT,
    source TEXT,
    source_name TEXT,
    event_type TEXT,
    severity TEXT,
    message TEXT,
    user TEXT,
    agent_id TEXT,
    raw TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    level INTEGER DEFAULT 3,
    rule_id TEXT,
    agent_name TEXT,
    ts TEXT,
    status TEXT DEFAULT 'open',
    source TEXT,
    mitre TEXT,
    ai_analysis TEXT,
    confidence REAL,
    raw TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS queue (
    id TEXT PRIMARY KEY,
    alert_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    assigned_to TEXT,
    sla_due TEXT,
    escalated INTEGER DEFAULT 0,
    notes TEXT DEFAULT '',
    ts TEXT
);
CREATE TABLE IF NOT EXISTS itdr_events (
    id TEXT PRIMARY KEY,
    ts TEXT,
    type TEXT,
    user TEXT,
    risk TEXT,
    severity TEXT,
    message TEXT,
    tenant TEXT,
    raw TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_itdr_ts ON itdr_events(ts);
CREATE TABLE IF NOT EXISTS itdr_cases (
    id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    user TEXT,
    events TEXT DEFAULT '[]',
    ts TEXT,
    updated TEXT
);
CREATE TABLE IF NOT EXISTS fim_events (
    id TEXT PRIMARY KEY,
    ts TEXT,
    agent TEXT,
    path TEXT,
    action TEXT,
    diff TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium'
);
CREATE INDEX IF NOT EXISTS idx_fim_ts ON fim_events(ts);
CREATE TABLE IF NOT EXISTS vuln_findings (
    id TEXT PRIMARY KEY,
    ts TEXT,
    agent TEXT,
    package TEXT,
    version TEXT,
    cve TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    source TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_vuln_sev ON vuln_findings(severity);
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    rule_id INTEGER,
    name TEXT,
    description TEXT,
    level INTEGER DEFAULT 3,
    groups TEXT DEFAULT '',
    mitigation TEXT DEFAULT '',
    status TEXT DEFAULT 'enabled',
    source TEXT DEFAULT 'custom',
    mitre TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT DEFAULT '',
    trigger TEXT DEFAULT '',
    actions TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1,
    ts TEXT
);
CREATE TABLE IF NOT EXISTS playbook_audit (
    id TEXT PRIMARY KEY,
    playbook_id TEXT,
    playbook_name TEXT,
    alert_id TEXT,
    action TEXT DEFAULT '',
    result TEXT DEFAULT '',
    ts TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    title TEXT,
    period TEXT DEFAULT '',
    ts TEXT,
    summary TEXT DEFAULT '{}',
    status TEXT DEFAULT 'ready'
);
CREATE TABLE IF NOT EXISTS external_tokens (
    name TEXT PRIMARY KEY,
    token TEXT DEFAULT '',
    updated TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS platform_orgs (
    id TEXT PRIMARY KEY,
    name TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS platform_users (
    id TEXT PRIMARY KEY,
    username TEXT,
    role TEXT DEFAULT 'viewer',
    org_id TEXT DEFAULT 'default',
    active INTEGER DEFAULT 1,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS platform_roles (
    role_key TEXT PRIMARY KEY,
    name TEXT,
    permissions TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS platform_webhooks (
    id TEXT PRIMARY KEY,
    url TEXT,
    events TEXT DEFAULT '[]',
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS agent_commands (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    command TEXT,
    args TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',  -- pending | sent | done | failed
    result TEXT DEFAULT '{}',
    created TEXT,
    updated TEXT
);
CREATE INDEX IF NOT EXISTS idx_cmds_agent ON agent_commands(agent_id, status);
"""


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn.commit()
    return _conn


def init():
    _connect()


def _rows(sql: str, params: tuple = ()) -> list[dict]:
    with _lock:
        cur = _connect().execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        return rows


def _one(sql: str, params: tuple = ()) -> dict | None:
    with _lock:
        cur = _connect().execute(sql, params)
        r = cur.fetchone()
        return dict(r) if r else None


def _exec(sql: str, params: tuple = ()) -> None:
    with _lock:
        cur = _connect().execute(sql, params)
        _connect().commit()
        return cur.lastrowid


def _execmany(sql: str, rows: list[tuple]) -> None:
    with _lock:
        _connect().executemany(sql, rows)
        _connect().commit()


# ── Agents ────────────────────────────────────────────────────────────────

def upsert_agent(agent_id: str, info: dict) -> None:
    """Record agent check-in from telemetry/poll/WS."""
    now = _now()
    existing = _one("SELECT * FROM agents WHERE id = ?", (agent_id,))
    if existing:
        _exec(
            "UPDATE agents SET hostname=?, platform=?, version=?, ip=?, last_seen=?, status=?, telemetry=? WHERE id=?",
            (
                info.get("hostname", existing["hostname"]),
                info.get("platform", existing["platform"]),
                info.get("agent_version", existing["version"]),
                info.get("ip", existing["ip"]),
                now,
                "online",
                json.dumps(info, default=str),
                agent_id,
            ),
        )
    else:
        _exec(
            "INSERT INTO agents (id, hostname, platform, version, ip, last_seen, status, telemetry, first_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                agent_id,
                info.get("hostname", agent_id),
                info.get("platform", "unknown"),
                info.get("agent_version", "?"),
                info.get("ip", ""),
                now,
                "online",
                json.dumps(info, default=str),
                now,
            ),
        )


def mark_agent_offline(agent_id: str) -> None:
    _exec("UPDATE agents SET status='offline' WHERE id=?", (agent_id,))


def list_agents() -> list[dict]:
    return _rows("SELECT * FROM agents ORDER BY last_seen DESC")


def get_agent(agent_id: str) -> dict | None:
    return _one("SELECT * FROM agents WHERE id = ?", (agent_id,))


# ── Events / SIEM ─────────────────────────────────────────────────────────

def add_events(events: list[dict]) -> int:
    rows = []
    for ev in events:
        rows.append(
            (
                _gen_id("evt"),
                ev.get("timestamp") or _now(),
                ev.get("source", "unknown"),
                ev.get("source_name", ""),
                ev.get("event_type", "unknown"),
                ev.get("severity", "medium"),
                str(ev.get("message", ""))[:2000],
                ev.get("user", ""),
                ev.get("agent_id", ""),
                json.dumps(ev, default=str),
            )
        )
    if rows:
        _execmany(
            "INSERT INTO events (id, ts, source, source_name, event_type, severity, message, user, agent_id, raw) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def query_events(filters: dict | None = None, limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM events WHERE 1=1"
    params: list = []
    f = filters or {}
    sev = f.get("severity")
    src = f.get("source")
    q = f.get("q")
    since = f.get("since")
    if sev:
        sql += " AND severity = ?"
        params.append(sev)
    if src:
        sql += " AND source = ?"
        params.append(src)
    if q:
        sql += " AND (message LIKE ? OR source_name LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    if since:
        sql += " AND ts >= ?"
        params.append(since)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    return _rows(sql, tuple(params))


def event_summary() -> dict:
    total = _one("SELECT COUNT(*) c FROM events")["c"]
    by_sev = {r["severity"]: r["c"] for r in _rows(
        "SELECT severity, COUNT(*) c FROM events GROUP BY severity")}
    by_source = {r["source"]: r["c"] for r in _rows(
        "SELECT source, COUNT(*) c FROM events GROUP BY source ORDER BY c DESC LIMIT 8")}
    last_hour = _one(
        "SELECT COUNT(*) c FROM events WHERE ts >= ?",
        (datetime.now(timezone.utc).replace(microsecond=0).isoformat(),),
    )["c"]
    return {
        "total": total,
        "by_severity": by_sev,
        "by_source": by_source,
        "last_hour": last_hour,
    }


# ── Alerts ────────────────────────────────────────────────────────────────

def add_alert(alert: dict) -> str:
    aid = _gen_id("alrt")
    _exec(
        "INSERT INTO alerts (id, title, severity, level, rule_id, agent_name, ts, status, source, mitre, ai_analysis, confidence, raw) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            aid,
            alert.get("title", "Alert"),
            alert.get("severity", "medium"),
            int(alert.get("level", 3)),
            str(alert.get("rule_id", "")),
            alert.get("agent_name", ""),
            alert.get("ts") or _now(),
            alert.get("status", "open"),
            alert.get("source", "custom"),
            alert.get("mitre", ""),
            alert.get("ai_analysis", ""),
            alert.get("confidence") if alert.get("confidence") is not None else None,
            json.dumps(alert, default=str),
        ),
    )
    return aid


def list_alerts(limit: int = 100, status: str = "") -> list[dict]:
    sql = "SELECT * FROM alerts"
    params: list = []
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    return _rows(sql, tuple(params))


def get_alert(alert_id: str) -> dict | None:
    return _one("SELECT * FROM alerts WHERE id = ?", (alert_id,))


def update_alert_status(alert_id: str, status: str) -> None:
    _exec("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))


def alert_metrics() -> dict:
    by_sev = {r["severity"]: r["c"] for r in _rows(
        "SELECT severity, COUNT(*) c FROM alerts WHERE status='open' GROUP BY severity")}
    by_status = {r["status"]: r["c"] for r in _rows(
        "SELECT status, COUNT(*) c FROM alerts GROUP BY status")}
    return {
        "open": sum(by_sev.values()),
        "by_severity": by_sev,
        "by_status": by_status,
        "total": _one("SELECT COUNT(*) c FROM alerts")["c"],
    }


# ── Queue ─────────────────────────────────────────────────────────────────

def queue_add(item: dict) -> str:
    qid = _gen_id("q")
    _exec(
        "INSERT INTO queue (id, alert_id, title, severity, status, assigned_to, sla_due, escalated, notes, ts) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            qid,
            item.get("alert_id", ""),
            item.get("title", "Alert"),
            item.get("severity", "medium"),
            item.get("status", "open"),
            item.get("assigned_to", ""),
            item.get("sla_due", ""),
            int(item.get("escalated", 0)),
            item.get("notes", ""),
            _now(),
        ),
    )
    return qid


def queue_list(status: str = "", user: str = "", limit: int = 100) -> list[dict]:
    sql = "SELECT * FROM queue WHERE 1=1"
    params: list = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if user:
        sql += " AND assigned_to = ?"
        params.append(user)
    sql += " ORDER BY escalated DESC, ts ASC LIMIT ?"
    params.append(limit)
    return _rows(sql, tuple(params))


def queue_update(qid: str, updates: dict) -> dict | None:
    item = _one("SELECT * FROM queue WHERE id = ?", (qid,))
    if not item:
        return None
    fields = {k: v for k, v in updates.items() if v is not None}
    if not fields:
        return item
    sets = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [qid]
    _exec(f"UPDATE queue SET {sets} WHERE id=?", tuple(params))
    return _one("SELECT * FROM queue WHERE id = ?", (qid,))


def queue_summary() -> dict:
    total = _one("SELECT COUNT(*) c FROM queue WHERE status != 'resolved'")["c"]
    by_sev = {r["severity"]: r["c"] for r in _rows(
        "SELECT severity, COUNT(*) c FROM queue WHERE status != 'resolved' GROUP BY severity")}
    by_status = {r["status"]: r["c"] for r in _rows(
        "SELECT status, COUNT(*) c FROM queue GROUP BY status")}
    escalated = _one("SELECT COUNT(*) c FROM queue WHERE escalated=1 AND status != 'resolved'")["c"]
    unassigned = _one("SELECT COUNT(*) c FROM queue WHERE (assigned_to IS NULL OR assigned_to='') AND status != 'resolved'")["c"]
    return {
        "total": total,
        "by_severity": by_sev,
        "by_status": by_status,
        "escalated": escalated,
        "unassigned": unassigned,
    }


# ── ITDR ──────────────────────────────────────────────────────────────────

def itdr_add_events(events: list[dict]) -> int:
    rows = []
    for ev in events:
        rows.append(
            (
                _gen_id("itdr"),
                ev.get("timestamp") or ev.get("ts") or _now(),
                ev.get("type", "unknown"),
                ev.get("user", ev.get("userId", "")),
                ev.get("risk", ""),
                ev.get("severity", "medium"),
                str(ev.get("message", ev.get("detail", "")))[:2000],
                ev.get("tenant", ""),
                json.dumps(ev, default=str),
            )
        )
    if rows:
        _execmany(
            "INSERT INTO itdr_events (id, ts, type, user, risk, severity, message, tenant, raw) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def itdr_list_events(limit: int = 200) -> list[dict]:
    return _rows("SELECT * FROM itdr_events ORDER BY ts DESC LIMIT ?", (limit,))


def itdr_add_case(case: dict) -> str:
    cid = _gen_id("itdr-c")
    _exec(
        "INSERT INTO itdr_cases (id, title, severity, status, user, events, ts, updated) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            cid,
            case.get("title", "ITDR case"),
            case.get("severity", "medium"),
            case.get("status", "open"),
            case.get("user", ""),
            json.dumps(case.get("events", []), default=str),
            _now(),
            _now(),
        ),
    )
    return cid


def itdr_list_cases(limit: int = 100) -> list[dict]:
    return _rows("SELECT * FROM itdr_cases ORDER BY ts DESC LIMIT ?", (limit,))


def itdr_summary() -> dict:
    total = _one("SELECT COUNT(*) c FROM itdr_events")["c"]
    by_type = {r["type"]: r["c"] for r in _rows(
        "SELECT type, COUNT(*) c FROM itdr_events GROUP BY type")}
    by_sev = {r["severity"]: r["c"] for r in _rows(
        "SELECT severity, COUNT(*) c FROM itdr_events GROUP BY severity")}
    high_risk = _one("SELECT COUNT(*) c FROM itdr_events WHERE severity IN ('critical','high')")["c"]
    open_cases = _one("SELECT COUNT(*) c FROM itdr_cases WHERE status='open'")["c"]
    return {
        "total": total,
        "by_type": by_type,
        "by_severity": by_sev,
        "high_risk": high_risk,
        "open_cases": open_cases,
    }


# ── FIM ───────────────────────────────────────────────────────────────────

def fim_add_events(events: list[dict]) -> int:
    rows = []
    for ev in events:
        rows.append(
            (
                _gen_id("fim"),
                ev.get("timestamp") or _now(),
                ev.get("agent", ev.get("agent_name", "")),
                ev.get("path", ""),
                ev.get("action", "modified"),
                str(ev.get("diff", ""))[:2000],
                ev.get("severity", "medium"),
            )
        )
    if rows:
        _execmany(
            "INSERT INTO fim_events (id, ts, agent, path, action, diff, severity) VALUES (?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def fim_list_events(limit: int = 200) -> list[dict]:
    return _rows("SELECT * FROM fim_events ORDER BY ts DESC LIMIT ?", (limit,))


def fim_summary() -> dict:
    total = _one("SELECT COUNT(*) c FROM fim_events")["c"]
    by_action = {r["action"]: r["c"] for r in _rows(
        "SELECT action, COUNT(*) c FROM fim_events GROUP BY action")}
    by_agent = {r["agent"]: r["c"] for r in _rows(
        "SELECT agent, COUNT(*) c FROM fim_events GROUP BY agent LIMIT 10")}
    return {"total": total, "by_action": by_action, "by_agent": by_agent}


# ── Vulnerabilities ───────────────────────────────────────────────────────

def vuln_add(findings: list[dict]) -> int:
    rows = []
    for f in findings:
        rows.append(
            (
                _gen_id("vuln"),
                _now(),
                f.get("agent", ""),
                f.get("package", ""),
                f.get("version", ""),
                f.get("cve", ""),
                f.get("severity", "medium"),
                f.get("status", "open"),
                f.get("source", ""),
            )
        )
    if rows:
        _execmany(
            "INSERT INTO vuln_findings (id, ts, agent, package, version, cve, severity, status, source) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def vuln_list(status: str = "", limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM vuln_findings WHERE 1=1"
    params: list = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    return _rows(sql, tuple(params))


def vuln_update(vid: str, updates: dict) -> dict | None:
    item = _one("SELECT * FROM vuln_findings WHERE id = ?", (vid,))
    if not item:
        return None
    fields = {k: v for k, v in updates.items() if k in ("status", "notes") and v is not None}
    if not fields:
        return item
    sets = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [vid]
    _exec(f"UPDATE vuln_findings SET {sets} WHERE id=?", tuple(params))
    return _one("SELECT * FROM vuln_findings WHERE id = ?", (vid,))


def vuln_summary() -> dict:
    total = _one("SELECT COUNT(*) c FROM vuln_findings WHERE status='open'")["c"]
    by_sev = {r["severity"]: r["c"] for r in _rows(
        "SELECT severity, COUNT(*) c FROM vuln_findings WHERE status='open' GROUP BY severity")}
    by_agent = {r["agent"]: r["c"] for r in _rows(
        "SELECT agent, COUNT(*) c FROM vuln_findings WHERE status='open' GROUP BY agent LIMIT 10")}
    return {"total": total, "by_severity": by_sev, "by_agent": by_agent}


# ── Rules ─────────────────────────────────────────────────────────────────

def rules_add(rule: dict) -> str:
    rid = _gen_id("rule")
    _exec(
        "INSERT INTO rules (id, rule_id, name, description, level, groups, mitigation, status, source, mitre) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            rid,
            int(rule.get("rule_id", 0)),
            rule.get("name", "Rule"),
            rule.get("description", ""),
            int(rule.get("level", 3)),
            json.dumps(rule.get("groups", []), default=str),
            rule.get("mitigation", ""),
            rule.get("status", "enabled"),
            rule.get("source", "custom"),
            rule.get("mitre", rule.get("mitre_technique", "")),
        ),
    )
    return rid


def rules_list(status: str = "", q: str = "", limit: int = 500) -> list[dict]:
    sql = "SELECT * FROM rules WHERE 1=1"
    params: list = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if q:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY rule_id ASC LIMIT ?"
    params.append(limit)
    return _rows(sql, tuple(params))


def rules_get(rid: str) -> dict | None:
    return _one("SELECT * FROM rules WHERE id = ?", (rid,))


def rules_update(rid: str, updates: dict) -> dict | None:
    item = _one("SELECT * FROM rules WHERE id = ?", (rid,))
    if not item:
        return None
    fields = {k: v for k, v in updates.items() if k in (
        "name", "description", "level", "status", "mitigation", "groups", "mitre") and v is not None}
    if not fields:
        return item
    if "groups" in fields and isinstance(fields["groups"], (list, tuple)):
        fields["groups"] = json.dumps(list(fields["groups"]), default=str)
    sets = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [rid]
    _exec(f"UPDATE rules SET {sets} WHERE id=?", tuple(params))
    return _one("SELECT * FROM rules WHERE id = ?", (rid,))


def rules_delete(rid: str) -> bool:
    cur = _exec("DELETE FROM rules WHERE id=?", (rid,))
    return cur > 0


# ── Playbooks ─────────────────────────────────────────────────────────────

def playbooks_add(pb: dict) -> str:
    pid = _gen_id("pb")
    _exec(
        "INSERT INTO playbooks (id, name, description, trigger, actions, enabled, ts) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            pid,
            pb.get("name", "Playbook"),
            pb.get("description", ""),
            pb.get("trigger", ""),
            json.dumps(pb.get("actions", []), default=str),
            int(pb.get("enabled", 1)),
            _now(),
        ),
    )
    return pid


def playbooks_list() -> list[dict]:
    return _rows("SELECT * FROM playbooks ORDER BY name")


def playbooks_get(pid: str) -> dict | None:
    return _one("SELECT * FROM playbooks WHERE id = ?", (pid,))


def playbooks_update(pid: str, updates: dict) -> dict | None:
    item = _one("SELECT * FROM playbooks WHERE id = ?", (pid,))
    if not item:
        return None
    fields = {k: v for k, v in updates.items() if k in (
        "name", "description", "trigger", "enabled") and v is not None}
    if "actions" in updates and isinstance(updates["actions"], (list, tuple)):
        fields["actions"] = json.dumps(list(updates["actions"]), default=str)
    if not fields:
        return item
    sets = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [pid]
    _exec(f"UPDATE playbooks SET {sets} WHERE id=?", tuple(params))
    return _one("SELECT * FROM playbooks WHERE id = ?", (pid,))


def playbooks_delete(pid: str) -> bool:
    cur = _exec("DELETE FROM playbooks WHERE id=?", (pid,))
    return cur > 0


def playbook_audit_add(entry: dict) -> str:
    aid = _gen_id("pba")
    _exec(
        "INSERT INTO playbook_audit (id, playbook_id, playbook_name, alert_id, action, result, ts) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            aid,
            entry.get("playbook_id", ""),
            entry.get("playbook_name", ""),
            entry.get("alert_id", ""),
            entry.get("action", ""),
            entry.get("result", ""),
            _now(),
        ),
    )
    return aid


def playbook_audit_list(limit: int = 100) -> list[dict]:
    return _rows("SELECT * FROM playbook_audit ORDER BY ts DESC LIMIT ?", (limit,))


# ── Reports ───────────────────────────────────────────────────────────────

def reports_add(report: dict) -> str:
    rid = _gen_id("rep")
    _exec(
        "INSERT INTO reports (id, title, period, ts, summary, status) VALUES (?,?,?,?,?,?)",
        (
            rid,
            report.get("title", "SOC Report"),
            report.get("period", ""),
            _now(),
            json.dumps(report.get("summary", {}), default=str),
            report.get("status", "ready"),
        ),
    )
    return rid


def reports_list(limit: int = 50) -> list[dict]:
    return _rows("SELECT * FROM reports ORDER BY ts DESC LIMIT ?", (limit,))


# ── Settings / Tokens ─────────────────────────────────────────────────────

def settings_get(key: str, default: str = "") -> str:
    r = _one("SELECT value FROM settings WHERE key = ?", (key,))
    return r["value"] if r else default


def settings_set(key: str, value: str) -> None:
    _exec(
        "INSERT INTO settings (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def settings_all() -> dict:
    return {r["key"]: r["value"] for r in _rows("SELECT key, value FROM settings")}


def token_get(name: str) -> str:
    return _one("SELECT token FROM external_tokens WHERE name = ?", (name,))["token"] if _one("SELECT token FROM external_tokens WHERE name = ?", (name,)) else ""


def token_set(name: str, token: str) -> None:
    _exec(
        "INSERT INTO external_tokens (name, token, updated) VALUES (?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET token=excluded.token, updated=excluded.updated",
        (name, token, _now()),
    )


# ── Agent command outbox ──────────────────────────────────────────────────

def enqueue_command(agent_id: str, command: str, args: dict | None = None) -> str:
    cid = _gen_id("cmd")
    _exec(
        "INSERT INTO agent_commands (id, agent_id, command, args, status, created, updated) "
        "VALUES (?,?,?,?,?,?,?)",
        (cid, agent_id, command, json.dumps(args or {}, default=str), "pending", _now(), _now()),
    )
    return cid


def pending_commands(agent_id: str, include_sent: bool = False) -> list[dict]:
    """Queued commands for an agent.

    'pending' = never delivered (the drain loop picks these up).
    'sent'    = delivered, awaiting the agent's result — only re-delivered on
                reconnect (include_sent=True), never by the 5s drain tick.
    """
    if include_sent:
        return _rows(
            "SELECT * FROM agent_commands WHERE agent_id = ? AND status IN ('pending','sent') "
            "ORDER BY created LIMIT 10",
            (agent_id,),
        )
    return _rows(
        "SELECT * FROM agent_commands WHERE agent_id = ? AND status='pending' ORDER BY created LIMIT 10",
        (agent_id,),
    )


def mark_command_sent(cmd_id: str) -> None:
    """Record delivery so the drain loop stops re-sending the same command."""
    _exec("UPDATE agent_commands SET status='sent', updated=? WHERE id=? AND status='pending'",
          (_now(), cmd_id))


def command_result(cmd_id: str, result: dict, status: str = "done") -> None:
    _exec(
        "UPDATE agent_commands SET result=?, status=?, updated=? WHERE id=?",
        (json.dumps(result, default=str), status, _now(), cmd_id),
    )


def get_command(cmd_id: str) -> dict | None:
    return _one("SELECT * FROM agent_commands WHERE id = ?", (cmd_id,))


def latest_commands(agent_id: str = "", limit: int = 50) -> list[dict]:
    sql = "SELECT * FROM agent_commands"
    params: list = []
    if agent_id:
        sql += " WHERE agent_id = ?"
        params.append(agent_id)
    sql += " ORDER BY created DESC LIMIT ?"
    params.append(limit)
    return _rows(sql, tuple(params))