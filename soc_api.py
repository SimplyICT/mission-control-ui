"""SOC API — route layer for the Wazuh SOC SPA.

Wires the existing (previously route-less) SOC domain modules into the
REST/WebSocket surface the React SPA expects:

  agents      : agent_telemetry.json (existing) + WS command outbox (soc_store)
  SIEM        : siem_ingest  (siem_logs.json)
  ITDR        : itdr_poller + itdr_detections (itdr_events.json / itdr_cases.json)
  EDR         : edr_actions  (SSH) + WS agent channel
  FIM         : fim_store    (fim_config.json / fim_events.json)
  VULN        : vuln_store   (cve_cache.json / vuln_results.json)
  Rules       : rule_engine  (custom_rules.json)
  Queue       : soc_queue    (soc_queue.json / soc_queue_notes.json)
  Threat intel: threat_intel (otx/cache)
  MITRE       : mitre_mapping
  Compliance  : compliance_mapping
  Playbooks   : playbook_engine
  Reports     : report_generator
  Settings    : settings_store
  Platform    : platform_core
  Autopilot   : ai_resolver / ai_cases.json (mirrors app.py /wazuh-api/autopilot/*)

Registered from app.py via include_router(). Auth: app.py middleware gates
/api/* except the public agent/SIEM-ingest paths.
"""

import concurrent.futures
import asyncio
import json
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

import soc_queue
import rule_engine
import siem_ingest
import itdr_poller
import fim_store
import vuln_store
import threat_intel
import mitre_mapping
import compliance_mapping
import report_generator
import playbook_engine
import settings_store
import platform_core

from soc_store import (
    enqueue_command, pending_commands, command_result,
    get_command, latest_commands, rules_get,
)

BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger("soc_api")

router = APIRouter(tags=["soc-api"])

LATEST_AGENT_VERSION = "1.1.0"
AGENT_TELEMETRY_FILE = BASE_DIR / "agent_telemetry.json"

# Dedicated pool for slow agent-result persistence (OSV lookups etc.) so it
# can never starve the event loop or the sync-endpoint threadpool.
_scan_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="socscan")


# ── Shared helpers ────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_telemetry() -> dict:
    try:
        if AGENT_TELEMETRY_FILE.exists():
            return json.loads(AGENT_TELEMETRY_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_telemetry(data: dict) -> None:
    try:
        # Atomic write — the systemd service runs 2 uvicorn workers that all
        # update this file; non-atomic writes truncate it under concurrency.
        import os as _os, tempfile as _tf
        fd, tmp = _tf.mkstemp(dir=str(AGENT_TELEMETRY_FILE.parent), suffix=".tmp")
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        _os.replace(tmp, str(AGENT_TELEMETRY_FILE))
    except Exception as e:
        logger.warning("telemetry save failed: %s", e)


def _agent_key(sysinfo: dict) -> str:
    platform = sysinfo.get("platform", "unknown")
    hostname = sysinfo.get("hostname", "unknown")
    return f"{platform}-{hostname}"


def _client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "")


def _agent_list() -> list[dict]:
    """Flat agent list from telemetry (shape used by /api/agents/all)."""
    telemetry = _load_telemetry()
    agents = []
    for key, info in telemetry.items():
        data = info.get("data", {}) if isinstance(info.get("data"), dict) else {}
        system = data.get("system", {}) if isinstance(data, dict) else {}
        default_host = key.split("-", 1)[-1] if "-" in key else key
        agents.append({
            "id": key,
            "name": system.get("hostname", system.get("host_name", default_host)),
            "hostname": system.get("hostname", default_host),
            "platform": system.get("platform", key.split("-")[0] if "-" in key else "unknown"),
            "version": system.get("agent_version", "?"),
            "ip": data.get("ip", info.get("ip", "")),
            "last_seen": info.get("last_seen", ""),
            "status": "online" if info.get("data", {}).get("status") == "online" else "offline",
            "os": {"platform": system.get("platform", "unknown")},
        })
    return agents


def _online_agent_ids() -> set:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    out = set()
    for key, info in _load_telemetry().items():
        try:
            last = datetime.fromisoformat(str(info.get("last_seen", "")).replace("Z", "+00:00"))
            if last >= cutoff and info.get("data", {}).get("status") == "online":
                out.add(key)
        except Exception:
            continue
    out |= connected_agents()
    return out


# ── WS agent registry ─────────────────────────────────────────────────────

_ws_connections: dict[str, WebSocket] = {}
_ws_loops: dict[str, asyncio.AbstractEventLoop] = {}
_ws_connected: set[str] = set()


def connected_agents() -> set[str]:
    """Agent keys with a currently-open WS connection."""
    return set(_ws_connected)


def _deliver_sync(agent_key: str, cmd: dict) -> bool:
    """Try to push a command to a connected WS agent (safe from sync handlers)."""
    ws = _ws_connections.get(agent_key)
    loop = _ws_loops.get(agent_key)
    if ws is None or loop is None:
        return False
    try:
        fut = asyncio.run_coroutine_threadsafe(ws.send_json({
            "type": "command",
            "id": cmd["id"],
            "command": cmd["command"],
            "args": json.loads(cmd.get("args") or "{}"),
        }), loop)
        # Fire-and-forget: command stays pending if the send ever fails;
        # the register drain retries it on the next reconnect.
        fut.add_done_callback(lambda f: None if not f.exception()
                              else logger.warning("WS send error: %s", f.exception()))
        return True
    except Exception as e:
        logger.warning("WS deliver failed: %s", e)
        return False


def _drain_loop() -> None:
    """Deliver pending commands to agents connected to THIS worker.

    With multiple uvicorn workers, an enqueue may land on a different worker
    than the agent's WebSocket.  This loop re-attempts delivery every few
    seconds, so cross-worker commands reach their agent promptly.
    """
    while True:
        try:
            for key in tuple(_ws_connected):
                for cmd in pending_commands(key)[:5]:
                    if _deliver_sync(key, cmd):
                        break  # delivered; next batch on next tick
        except Exception as e:
            logger.warning("drain error: %s", e)
        time.sleep(5)


import threading as _threading
_threading.Thread(target=_drain_loop, daemon=True, name="cmd-drain").start()


async def _agent_ws_loop(ws: WebSocket, legacy: bool = False):
    await ws.accept()
    agent_key = None
    try:
        while True:
            msg = await ws.receive_json()
            kind = msg.get("type", "")
            if kind == "register":
                sysinfo = msg.get("data", {})
                agent_key = _agent_key(sysinfo)
                _ws_connections[agent_key] = ws
                _ws_loops[agent_key] = asyncio.get_running_loop()
                _ws_connected.add(agent_key)
                telemetry = _load_telemetry()
                entry = telemetry.setdefault(agent_key, {"data": {}})
                entry["data"] = {"system": sysinfo, "status": "online"}
                entry["last_seen"] = _now()
                _save_telemetry(telemetry)
                # Registration ack FIRST (client's auto-update window).
                await ws.send_json({
                    "type": "registered",
                    "agent_id": sysinfo.get("agent_id", agent_key),
                    "latest_version": LATEST_AGENT_VERSION,
                    "needs_update": str(sysinfo.get("agent_version", "")) != LATEST_AGENT_VERSION,
                })
                # Drain pending command outbox.
                for cmd in pending_commands(agent_key):
                    await ws.send_json({
                        "type": "command",
                        "id": cmd["id"],
                        "command": cmd["command"],
                        "args": json.loads(cmd.get("args") or "{}"),
                    })
            elif kind == "result" and agent_key:
                command_result(msg.get("id", ""), msg.get("result", {}))
                loop_local = asyncio.get_running_loop()
                loop_local.run_in_executor(_scan_executor, _persist_agent_result,
                                           agent_key, msg.get("command", ""), msg.get("result", {}))
            elif kind == "telemetry" and agent_key:
                telemetry = _load_telemetry()
                entry = telemetry.setdefault(agent_key, {"data": {}})
                entry["data"] = {
                    "system": entry["data"].get("system", {}),
                    "status": "online",
                    "telemetry": msg.get("data", {}),
                }
                entry["last_seen"] = _now()
                _save_telemetry(telemetry)
                if msg.get("id"):
                    command_result(msg["id"], {"success": True, "telemetry": True})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("WS agent error: %s", e)
    finally:
        if agent_key:
            _ws_connections.pop(agent_key, None)
            _ws_loops.pop(agent_key, None)
            _ws_connected.discard(agent_key)
            telemetry = _load_telemetry()
            if agent_key in telemetry and isinstance(telemetry[agent_key].get("data"), dict):
                telemetry[agent_key]["data"]["status"] = "offline"
                _save_telemetry(telemetry)


@router.websocket("/api/agent/ws")
async def agent_ws(ws: WebSocket):
    await _agent_ws_loop(ws)


# Legacy EDR agent endpoint (edr_agent.py) — same envelope, same loop.
@router.websocket("/api/edr/agent/ws")
async def edr_agent_ws(ws: WebSocket):
    await _agent_ws_loop(ws, legacy=True)


# ── Agent result persisters (FIM / vuln) ──────────────────────────────────

FIM_BASELINE_FILE = BASE_DIR / "fim_baselines.json"
VULN_RESULTS_FILE = BASE_DIR / "vuln_results.json"


def _load_fim_baselines() -> dict:
    try:
        if FIM_BASELINE_FILE.exists():
            return json.loads(FIM_BASELINE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_fim_baselines(data: dict) -> None:
    try:
        import tempfile as _tf
        fd, tmp = _tf.mkstemp(dir=str(FIM_BASELINE_FILE.parent), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, str(FIM_BASELINE_FILE))
    except Exception:
        pass


def _persist_fim_result(agent_key: str, result: dict) -> None:
    """Baseline + diff a fim_scan result into fim_store events."""
    files = result.get("files", [])
    if not files:
        return
    baselines = _load_fim_baselines()
    baseline = baselines.get(agent_key, {})
    events = []
    changed = False
    for f in files:
        path = f.get("path", "")
        if not path:
            continue
        if f.get("exists"):
            new_hash = f.get("hash", "")
            if path in baseline and baseline[path] != new_hash:
                events.append({"agent": agent_key, "path": path, "action": "modified",
                               "timestamp": _now(), "severity": "high"})
            baseline[path] = new_hash
        elif path in baseline:
            events.append({"agent": agent_key, "path": path, "action": "deleted",
                           "timestamp": _now(), "severity": "critical"})
            baseline.pop(path, None)
        else:
            baseline[path] = ""
    if events:
        fim_store.store_events_batch(events)
    baselines[agent_key] = baseline
    _save_fim_baselines(baselines)


def _osv_ecosystem(source: str) -> str:
    return {"dpkg": "Debian", "rpm": "Rocky Linux", "pip": "PyPI",
            "wmic": "Windows", "pkgutil": "macOS"}.get(source, "Debian")


def _osv_severity(vuln: dict) -> str:
    sev = (vuln.get("database_specific") or {}).get("severity", "")
    if sev:
        return sev.lower()
    # CVSS v3 base vector → rough severity band.
    for s in vuln.get("severity", []):
        vec = s.get("score", "")
        if vec.startswith("CVSS:3"):
            try:
                base = float(vec.split("CVSS:3.1/")[-1].split("/AV")[0]) if "AV" in vec else 0.0
            except Exception:
                base = 0.0
            # Score not in vector itself; fall back to attack-vector heuristic.
            base = 9.8 if "AV:N" in vec and "PR:N" in vec else 7.5 if "AV:N" in vec else 5.0
            if base >= 9.0: return "critical"
            if base >= 7.0: return "high"
            if base >= 4.0: return "medium"
            return "low"
    return "medium"


def _osv_find(packages: list[dict]) -> list[dict]:
    """Query the OSV API for known vulnerabilities in the package set."""
    packages = packages[:300]
    if not packages:
        return []
    findings = []
    batch = []
    for p in packages:
        q = {"package": {"name": p.get("name", ""),
                         "ecosystem": _osv_ecosystem(p.get("source", ""))}}
        if p.get("version"):
            q["version"] = p["version"]
        if q["package"]["name"]:
            batch.append(q)
    if not batch:
        return []
    try:
        r = requests.post("https://api.osv.dev/v1/querybatch",
                          json={"queries": batch}, timeout=15)
        if r.ok:
            for query, resp in zip(batch, r.json().get("results", [])):
                pkg_name = query["package"]["name"]
                version = next((p.get("version", "") for p in packages if p.get("name") == pkg_name), "")
                for vuln in resp.get("vulns", [])[:10]:
                    findings.append({
                        "cve_id": vuln.get("id", ""),
                        "severity": _osv_severity(vuln),
                        "score": 0,
                        "package_name": pkg_name,
                        "package_version": version,
                        "description": (vuln.get("summary") or vuln.get("details", ""))[:500],
                        "published": vuln.get("published", ""),
                        "source": "osv",
                    })
    except Exception as e:
        logger.warning("OSV lookup failed: %s", e)
    seen = set()
    deduped = []
    for f in findings:
        k = (f["cve_id"], f["package_name"], f["package_version"])
        if k not in seen:
            seen.add(k)
            deduped.append(f)
    return deduped[:500]


def _persist_vuln_result(agent_key: str, result: dict) -> None:
    packages = result.get("packages", [])
    if not packages:
        return
    vuln_store.store_packages(agent_key, packages)
    findings = _osv_find(packages)
    results = {}
    if VULN_RESULTS_FILE.exists():
        try:
            results = json.loads(VULN_RESULTS_FILE.read_text())
        except Exception:
            pass
    results[agent_key] = {
        "findings": findings,
        "total_packages": len(packages),
        "vulnerable_count": len(findings),
        "scanned_at": _now(),
    }
    import tempfile as _tf
    fd, tmp = _tf.mkstemp(dir=str(VULN_RESULTS_FILE.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    os.replace(tmp, str(VULN_RESULTS_FILE))


def _persist_agent_result(agent_key: str, command: str, result: dict) -> None:
    if command == "fim_scan":
        _persist_fim_result(agent_key, result)
    elif command in ("packages", "vuln_packages", "collect"):
        _persist_vuln_result(agent_key, result)


def _enqueue_to_online(command: str, args: dict | None = None, limit: int = 20) -> dict:
    agents = sorted(_online_agent_ids())[:limit]
    queued = 0
    for key in agents:
        try:
            from soc_store import get_command
            cmd_id = enqueue_command(key, command, args or {})
            cmd = get_command(cmd_id)
            _deliver_sync(key, cmd)
            queued += 1
        except Exception:
            continue
    return {"queued": queued, "agents": agents}


@router.post("/api/fim/scan")
async def api_fim_scan():
    return _enqueue_to_online("fim_scan", {"paths": []})


@router.post("/api/vuln/scan")
async def api_vuln_scan():
    return _enqueue_to_online("vuln_packages", {})


# ── SCA (security configuration assessment) ───────────────────────────────

@router.get("/api/sca/overview")
def api_sca_overview():
    try:
        scores = compliance_mapping.get_framework_scores()
    except Exception:
        scores = {}
    policies = []
    for key, fw in scores.items():
        policies.append({
            "id": key, "name": fw.get("name", key),
            "framework": key, "score": fw.get("overall_score", 0),
            "status": fw.get("status", "needs_work"),
        })
    avg = round(sum(p["score"] for p in policies) / len(policies)) if policies else 0
    return {
        "total_policies": len(policies),
        "avg_score": avg,
        "status": "compliant" if avg >= 80 else "needs_work" if avg >= 50 else "non_compliant",
        "policies": policies,
    }


@router.get("/api/sca/policies")
def api_sca_policies():
    try:
        scores = compliance_mapping.get_framework_scores()
    except Exception:
        scores = {}
    out = []
    for key, fw in scores.items():
        try:
            detail = compliance_mapping.get_framework_detail(key) or {}
            requirements = []
            for req in detail.get("requirements", [])[:20]:
                requirements.append({
                    "id": req.get("id", ""), "title": req.get("description", ""),
                    "score": req.get("score", 0),
                    "passed": (req.get("score", 0) or 0) >= 80,
                })
            out.append({
                "id": key, "name": fw.get("name", key), "score": fw.get("overall_score", 0),
                "status": fw.get("status", "needs_work"),
                "description": fw.get("description", ""),
                "checks": requirements,
            })
        except Exception:
            continue
    return {"policies": out}

@router.get("/api/agents")
def api_agents_list(request: Request, limit: int = 500, select: str = ""):
    """Wazuh-style agent list (used by EDR deploy tabs)."""
    agents = _agent_list()[:limit]
    if select:
        fields = [f.strip() for f in select.split(",") if f.strip()]
        out = []
        for a in agents:
            row = {}
            for f in fields:
                if f == "os.platform":
                    row["os"] = {"platform": a.get("platform", "unknown")}
                else:
                    row[f] = a.get(f)
            out.append(row)
        return {"affected_items": out}
    return {"affected_items": [{"id": a["id"], "name": a["name"], "ip": a["ip"],
                                "os": {"platform": a["platform"]}, "status": a["status"],
                                "version": a["version"]} for a in agents]}


@router.get("/api/agents/{agent_id}/telemetry")
def api_agent_telemetry(agent_id: str):
    telemetry = _load_telemetry()
    info = telemetry.get(agent_id) or {}
    # UI reads tel.data?.data then telemetry?.data?.system (double nesting tolerated).
    return {"data": {"data": info.get("data", {})}}


@router.post("/api/agents/update")
async def api_agents_update(request: Request):
    body = await request.json()
    agent_ids = body.get("agent_ids") or []
    updated = 0
    failed = 0
    server = os.getenv("SOC_SERVER", "173.208.232.91:8095")
    for aid in agent_ids:
        try:
            from soc_store import get_command
            cmd_id = enqueue_command(aid, "self_update", {"server": server})
            cmd = get_command(cmd_id)
            _deliver_sync(aid, cmd)
            updated += 1
        except Exception:
            failed += 1
    return {"updated": updated, "failed": failed}


@router.post("/api/agent/{agent_id}/result")
async def api_agent_result(agent_id: str, request: Request):
    try:
        body = await request.json()
        command_result(body.get("id", ""), body.get("result", {}))
        _persist_agent_result(agent_id, body.get("command", ""), body.get("result", {}))
    except Exception:
        pass
    return {}


@router.get("/api/agent/install/windows-batch")
def api_agent_install_batch():
    f = BASE_DIR / "install_windows.cmd"
    if f.exists():
        return HTMLResponse(f.read_text(errors="replace"), status_code=200)
    return JSONResponse({"error": "installer not found"}, status_code=404)


@router.get("/api/agent/install/windows-oneliner")
def api_agent_install_oneliner():
    f = BASE_DIR / "install_windows_oneliner.ps1"
    if f.exists():
        return HTMLResponse(f.read_text(errors="replace"), status_code=200)
    return JSONResponse({"error": "installer not found"}, status_code=404)


# ── Dashboard ─────────────────────────────────────────────────────────────

@router.get("/api/dashboard")
def api_dashboard():
    agents = _agent_list()
    online_ids = _online_agent_ids()
    online = len(online_ids)
    by_platform: dict[str, int] = {}
    for a in agents:
        by_platform[a["platform"]] = by_platform.get(a["platform"], 0) + 1

    siem = siem_ingest.get_summary()
    itdr = itdr_poller.get_summary()

    queue_items = soc_queue.get_queue(None)
    queue_sum = _queue_summary(queue_items)

    detections = []
    for item in queue_items[:8]:
        detections.append({
            "severity": item.get("severity", "medium"),
            "title": item.get("title", ""),
            "user": item.get("agent_name") or item.get("source", ""),
            "timestamp": item.get("created_at", ""),
        })

    try:
        from ai_resolver import get_stats, list_cases
        stats = get_stats()
        cases = list_cases()
    except Exception:
        stats, cases = {}, []

    return {
        "agents": {
            "total": len(agents),
            "online": online,
            "offline": max(0, len(agents) - online),
            "by_platform": by_platform,
        },
        "siem": {"total_logs": siem.get("total_logs", 0), "by_source": siem.get("by_source", {})},
        "itdr": {"critical": itdr.get("critical", 0), "high": itdr.get("high", 0),
                 "total_events": itdr.get("total_events", 0),
                 "sources_configured": bool(itdr.get("sources_configured"))},
        "queue": queue_sum,
        "detections": detections,
        "detection_count": len(queue_items),
        "cases": {
            "open": sum(1 for c in cases if c.get("status") == "open"),
            "awaiting_approval": sum(1 for c in cases if c.get("status") == "awaiting_approval"),
            "auto_resolved": sum(1 for c in cases if c.get("status") in ("resolved", "auto_resolved")),
            "last_24h": stats.get("last_24h", 0),
        },
    }


def _queue_summary(items: list[dict]) -> dict:
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    unassigned = 0
    breached = 0
    for it in items:
        if it.get("status") not in ("resolved", "closed"):
            by_severity[it.get("severity", "low")] = by_severity.get(it.get("severity", "low"), 0) + 1
        by_status[it.get("status", "new")] = by_status.get(it.get("status", "new"), 0) + 1
        if not it.get("assigned_to"):
            unassigned += 1
        if it.get("sla_breached"):
            breached += 1
    return {
        "total": sum(1 for it in items if it.get("status") not in ("resolved", "closed")),
        "unassigned": unassigned,
        "sla_breached": breached,
        "by_severity": by_severity,
        "by_status": by_status,
    }


# ── SIEM ──────────────────────────────────────────────────────────────────

@router.get("/api/siem/summary")
def api_siem_summary():
    return siem_ingest.get_summary()


@router.get("/api/siem/logs")
def api_siem_logs(limit: int = 200, severity: str = "", q: str = "", source: str = ""):
    filters = {}
    if severity:
        filters["severity"] = severity
    if source:
        filters["source"] = source
    logs, total = siem_ingest.query_logs(filters or None, limit=limit)
    if q:
        ql = q.lower()
        logs = [l for l in logs if ql in str(l.get("message", "")).lower()
                or ql in str(l.get("source_name", "")).lower()
                or ql in str(l.get("ip_src", "")).lower()]
        total = len(logs)
    return {"logs": logs, "total": total}


@router.post("/api/siem/ingest")
async def api_siem_ingest(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"status": "error", "message": "invalid JSON"}
    if isinstance(body, list):
        await asyncio.get_running_loop().run_in_executor(
            _scan_executor, siem_ingest.ingest_batch, body)
        return {"status": "ok", "ingested": len(body)}
    return await asyncio.get_running_loop().run_in_executor(
        _scan_executor, siem_ingest.ingest_json, body)


# ── ITDR ──────────────────────────────────────────────────────────────────

def _itdr_event_out(ev: dict) -> dict:
    return {
        "id": ev.get("id", ""),
        "created_at": ev.get("created_at") or ev.get("timestamp") or ev.get("ts", ""),
        "source": ev.get("source", "unknown"),
        "user": ev.get("user", ev.get("userId", "")),
        "activity": ev.get("activity", ""),
        "risk_type": ev.get("risk_type", ""),
        "ip_address": ev.get("ip_address", ev.get("ip", "")),
        "risk_level": ev.get("risk_level", ev.get("risk", "")),
        "status": ev.get("status", ev.get("severity", "medium")),
        "severity": ev.get("severity", "medium"),
        "tenant_id": ev.get("tenant_id", "default"),
        "tenant_name": ev.get("tenant_name", ev.get("tenant_id", "default")),
        "country": ev.get("country", ""),
        "location": ev.get("location", ""),
        "app": ev.get("app", ""),
    }


@router.get("/api/itdr/summary")
def api_itdr_summary():
    return itdr_poller.get_summary()


@router.get("/api/itdr/events")
def api_itdr_events(limit: int = 100, tenant: str = ""):
    events = itdr_poller.get_events(filters={"tenant_id": tenant.strip() or None}, limit=limit)
    return {"events": [_itdr_event_out(e) for e in events]}


@router.get("/api/itdr/cases")
def api_itdr_cases(tenant: str = ""):
    cases = []
    for c in itdr_poller.get_cases(tenant_id=tenant.strip() or None):
        cases.append({
            "id": c.get("id", ""),
            "timestamp": c.get("created_at") or c.get("timestamp") or c.get("ts", ""),
            "severity": c.get("severity", "medium"),
            "title": c.get("title", "ITDR case"),
            "user": c.get("user", ""),
            "status": c.get("status", "open"),
            "tenant_id": c.get("tenant_id", "default"),
            "tenant_name": c.get("tenant_name", c.get("tenant_id", "default")),
            "detection_type": c.get("detection_type", ""),
            "description": c.get("description", ""),
            "event_id": c.get("event_id", ""),
        })
    return {"cases": cases}


# ── ITDR tenants (M365 multi-tenant registry) ─────────────────────────────

@router.get("/api/itdr/tenants")
def api_itdr_tenants():
    return {"tenants": itdr_poller.get_tenants()}


@router.post("/api/itdr/tenants")
async def api_itdr_tenants_create(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    name = (body.get("name") or "").strip()
    if not name:
        return {"success": False, "error": "name is required"}
    try:
        tenant = itdr_poller.create_tenant(
            name=name,
            tenant_id=(body.get("tenant_id") or "").strip(),
            org_id=(body.get("org_id") or "default").strip(),
            env_prefix=(body.get("env_prefix") or "").strip(),
        )
    except ValueError as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "tenant": tenant}


@router.patch("/api/itdr/tenants/{tenant_id}")
async def api_itdr_tenants_update(tenant_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    fields = {k: body[k] for k in ("enabled", "name", "tenant_id", "org_id") if k in body}
    if not fields:
        return {"success": False, "error": "no updatable fields supplied"}
    tenant = itdr_poller.update_tenant(tenant_id, fields)
    if tenant is None:
        return {"success": False, "error": "tenant not found"}
    return {"success": True, "tenant": tenant}


@router.delete("/api/itdr/tenants/{tenant_id}")
def api_itdr_tenants_delete(tenant_id: str):
    if not itdr_poller.delete_tenant(tenant_id):
        return {"success": False, "error": "tenant not found or is the legacy 'default' tenant"}
    return {"success": True}


@router.post("/api/itdr/poll")
def api_itdr_poll():
    return itdr_poller.poll_all_tenants()


@router.post("/api/itdr/poll/{tenant_id}")
def api_itdr_poll_tenant(tenant_id: str):
    return itdr_poller.poll_tenant(tenant_id)


# ── EDR ───────────────────────────────────────────────────────────────────

def _edr_agent_snapshot(agent_key: str) -> dict:
    """Cached telemetry snapshot for an agent (WS-collected), plus isolation state."""
    telemetry = _load_telemetry()
    info = telemetry.get(agent_key, {})
    data = info.get("data", {}) if isinstance(info.get("data"), dict) else {}
    out = {"system": data.get("system", {})}
    tel = data.get("telemetry", {})
    if isinstance(tel, dict):
        out.update({k: v for k, v in tel.items() if k in ("processes", "network", "disks")})
    return out


def _enqueue_and_deliver(agent_key: str, command: str, args: dict | None = None) -> dict:
    from soc_store import get_command
    cmd_id = enqueue_command(agent_key, command, args or {})
    cmd = get_command(cmd_id)
    if _deliver_sync(agent_key, cmd):
        return {"success": True, "pending": True, "id": cmd["id"], "delivered": True}
    return {"success": True, "pending": True, "id": cmd["id"], "delivered": False}


@router.get("/api/edr/summary")
def api_edr_summary():
    agents = _agent_list()
    online_ids = _online_agent_ids()
    linux = [a for a in agents if a["platform"] in ("linux", "ubuntu")]
    windows = [a for a in agents if a["platform"] == "windows"]
    isolation = _load_isolation()
    isolated = [{"agent_id": k, "isolated_at": v.get("isolated_at", "")} for k, v in isolation.items()]
    return {
        "total_agents": len(agents),
        "active_agents": len(online_ids),
        "disconnected_agents": max(0, len(agents) - len(online_ids)),
        "linux_agents": len(linux),
        "windows_agents": len(windows),
        "ssh_reachable": 0,
        "isolated_count": len(isolated),
        "isolated_agents": isolated,
    }


def _load_isolation() -> dict:
    try:
        f = BASE_DIR / "edr_isolation.json"
        if f.exists():
            return json.loads(f.read_text())
    except Exception:
        pass
    return {}


def _save_isolation(state: dict) -> None:
    try:
        (BASE_DIR / "edr_isolation.json").write_text(json.dumps(state, indent=2, default=str))
    except Exception as e:
        logger.warning("isolation save failed: %s", e)


@router.get("/api/edr/audit")
def api_edr_audit(limit: int = 100):
    try:
        f = BASE_DIR / "edr_audit.json"
        if f.exists():
            entries = json.loads(f.read_text())
        else:
            entries = []
    except Exception:
        entries = []
    entries = [e for e in entries if isinstance(e, dict)]
    return {"entries": entries[-limit:]}


@router.get("/api/edr/public-key")
def api_edr_public_key():
    key_path = os.path.expanduser("~/.ssh/id_ed25519.pub")
    try:
        return {"ssh_key": open(key_path).read().strip()}
    except Exception:
        return {"ssh_key": ""}


@router.get("/api/edr/agent/{agent_id}/check-ssh")
def api_edr_check_ssh(agent_id: str):
    telemetry = _load_telemetry()
    info = telemetry.get(agent_id, {})
    data = info.get("data", {}) if isinstance(info.get("data"), dict) else {}
    ip = data.get("ip", "")
    hostname = data.get("system", {}).get("hostname", agent_id)
    if not ip:
        return {"success": False, "error": "No management IP for agent (WS channel only)", "ip": ip, "user": ""}
    try:
        import edr_actions
        return edr_actions.check_ssh_access(agent_id)
    except Exception as e:
        return {"success": False, "error": str(e)[:60], "ip": ip, "user": ""}


@router.get("/api/edr/agent/{agent_id}/deploy-key")
def api_edr_deploy_key(agent_id: str):
    ip = _load_telemetry().get(agent_id, {}).get("data", {}).get("ip", "")
    key = api_edr_public_key().get("ssh_key", "")
    cmd = f"curl -sL https://mc.simplyict.com.au/mission/wazuh-soc.html >/dev/null; echo '{key}' >> ~/.ssh/authorized_keys"
    return {"success": bool(ip), "ip": ip, "user": "root", "command": cmd}


@router.get("/api/edr/agent/{agent_id}/processes")
def api_edr_processes(agent_id: str):
    snap = _edr_agent_snapshot(agent_id)
    procs = snap.get("processes") or []
    if not procs:
        _enqueue_and_deliver(agent_id, "collect")
        return {"processes": [], "error": "Collecting data from agent…"}
    return {"processes": procs}


@router.get("/api/edr/agent/{agent_id}/process-tree")
def api_edr_process_tree(agent_id: str):
    snap = _edr_agent_snapshot(agent_id)
    procs = snap.get("processes") or []
    if not procs:
        _enqueue_and_deliver(agent_id, "collect")
        return {"tree": [], "error": "Collecting data from agent…"}
    tree = []
    by_pid = {}
    for p in procs:
        pid = str(p.get("pid", ""))
        row = {
            "pid": pid,
            "ppid": str(p.get("ppid", p.get("parent_pid", "1"))),
            "cpu": p.get("cpu", 0),
            "command": p.get("command", p.get("name", "")),
            "depth": 0,
            "has_children": False,
        }
        by_pid[pid] = row
        tree.append(row)
    for row in tree:
        parent = by_pid.get(row["ppid"])
        if parent:
            row["depth"] = parent["depth"] + 1
            parent["has_children"] = True
    return {"tree": tree}


@router.get("/api/edr/agent/{agent_id}/persistence")
def api_edr_persistence(agent_id: str):
    snap = _edr_agent_snapshot(agent_id)
    entries = snap.get("persistence") or []
    if not entries:
        _enqueue_and_deliver(agent_id, "collect")
        return {"entries": [], "error": "Collecting data from agent…"}
    return {"entries": entries}


@router.get("/api/edr/agent/{agent_id}/network")
def api_edr_network(agent_id: str):
    snap = _edr_agent_snapshot(agent_id)
    conns = snap.get("network") or []
    if not conns:
        _enqueue_and_deliver(agent_id, "collect")
        return {"connections": [], "error": "Collecting data from agent…"}
    return {"connections": conns}


@router.post("/api/edr/agent/{agent_id}/kill")
async def api_edr_kill(agent_id: str, request: Request):
    body = await request.json()
    pid = body.get("pid", "")
    return _enqueue_and_deliver(agent_id, "kill", {"pid": pid, "signal": body.get("signal", "TERM")})


@router.post("/api/edr/agent/{agent_id}/isolate")
async def api_edr_isolate(agent_id: str):
    state = _load_isolation()
    state[agent_id] = {"isolated_at": _now()}
    _save_isolation(state)
    _enqueue_and_deliver(agent_id, "isolate")
    return {"success": True, "agent_id": agent_id}


@router.post("/api/edr/agent/{agent_id}/release")
async def api_edr_release(agent_id: str):
    state = _load_isolation()
    state.pop(agent_id, None)
    _save_isolation(state)
    _enqueue_and_deliver(agent_id, "release")
    return {"success": True, "agent_id": agent_id}


# ── FIM ───────────────────────────────────────────────────────────────────

@router.get("/api/fim/summary")
def api_fim_summary():
    s = fim_store.get_summary()
    return {
        "total_changes": s.get("total_changes", s.get("total", 0)),
        "by_severity": s.get("by_severity", {}),
        "by_change_type": s.get("by_change_type", {}),
        "watched_paths": s.get("watched_paths", 0),
    }


@router.get("/api/fim/events")
def api_fim_events(limit: int = 100):
    events = fim_store.get_events(filters=None, limit=limit)
    out = []
    for ev in events:
        out.append({
            "filepath": ev.get("filepath", ev.get("path", "")),
            "timestamp": ev.get("timestamp", ev.get("ts", "")),
            "hostname": ev.get("hostname", ev.get("agent", "")),
            "change_type": ev.get("change_type", ev.get("action", "modified")),
            "severity": ev.get("severity", "medium"),
        })
    return {"events": out}


@router.get("/api/fim/config")
def api_fim_config(platform: str = "linux"):
    return {"paths": fim_store.get_config(platform)}


def _fim_index_for_path(platform: str, path: str) -> int | None:
    cfg = fim_store.get_config(platform)
    for i, p in enumerate(cfg):
        if p.get("path") == path:
            return i
    return None


@router.post("/api/fim/config/linux")
async def api_fim_config_add(request: Request):
    body = await request.json()
    paths = fim_store.add_path("linux", {"path": body.get("path", ""),
                                          "severity": body.get("severity", "medium"),
                                          "type": body.get("type", "custom"),
                                          "enabled": True})
    return {"paths": paths}


@router.put("/api/fim/config/linux/{path:path}")
async def api_fim_config_update(path: str, request: Request):
    body = await request.json()
    idx = _fim_index_for_path("linux", path)
    if idx is None:
        return JSONResponse({"error": "path not found"}, status_code=404)
    paths = fim_store.update_path("linux", idx, {"enabled": body.get("enabled", True)})
    return {"paths": paths}


@router.delete("/api/fim/config/linux/{path:path}")
def api_fim_config_delete(path: str):
    idx = _fim_index_for_path("linux", path)
    if idx is None:
        return JSONResponse({"error": "path not found"}, status_code=404)
    paths = fim_store.delete_path("linux", idx)
    return {"paths": paths}


# ── Vulnerabilities ───────────────────────────────────────────────────────

@router.get("/api/vuln/summary")
def api_vuln_summary():
    s = vuln_store.get_summary()
    return {
        "total_findings": s.get("total_findings", s.get("total", 0)),
        "by_severity": s.get("by_severity", {}),
        "cves_in_db": s.get("cves_in_db", len(vuln_store.load_cve_cache())),
        "agents_scanned": s.get("agents_scanned", 0),
    }


@router.get("/api/vuln/findings")
def api_vuln_findings(severity: str = ""):
    findings = vuln_store.get_findings(severity=severity)
    return findings


@router.post("/api/vuln/update-cve")
async def api_vuln_update_cve():
    try:
        result = vuln_store.update_cve_cache()
        return {"fetched": result.get("fetched", result.get("count", 0))}
    except Exception as e:
        return {"fetched": 0, "error": str(e)}


# ── MITRE ─────────────────────────────────────────────────────────────────

@router.get("/api/mitre/matrix")
def api_mitre_matrix():
    return mitre_mapping.get_mitre_matrix()


@router.get("/api/mitre/techniques")
def api_mitre_techniques():
    return mitre_mapping.get_mitre_techniques()


# ── Compliance ────────────────────────────────────────────────────────────

@router.get("/api/compliance/overview")
def api_compliance_overview():
    return compliance_mapping.get_framework_scores()


@router.get("/api/compliance/{framework}")
def api_compliance_detail(framework: str):
    detail = compliance_mapping.get_framework_detail(framework)
    if detail is None:
        return JSONResponse({"error": "framework not found"}, status_code=404)
    return detail


# ── Threat Intel ──────────────────────────────────────────────────────────

_OTX_FILE = BASE_DIR / "otx_data.json"
_TYPE_MAP = {"ip": "IPv4", "domain": "domain", "hash": "MD5", "url": "URL"}


def _otx_iocs() -> list[dict]:
    """Serve IOCs from otx_data.json (offline, no API key) when cache is empty."""
    try:
        if _OTX_FILE.exists():
            data = json.loads(_OTX_FILE.read_text())
            out = []
            for i in data.get("iocs", []):
                t = i.get("type", "")
                label = _TYPE_MAP.get(t)
                if not label and t in ("md5", "sha1", "sha256"):
                    label = t.upper()
                if not label:
                    label = t.title() if t else "other"
                out.append({
                    "indicator": i.get("value", ""),
                    "type": label,
                    "source": "OTX",
                    "description": i.get("category", ""),
                    "tags": [i.get("category", "")] if i.get("category") else [],
                })
            return out
    except Exception:
        pass
    return []


def _threat_summary() -> dict:
    s = threat_intel.get_summary()
    if s.get("total_iocs", 0) > 0:
        return s
    iocs = _otx_iocs()
    if not iocs:
        return s
    by_type: dict[str, int] = {}
    for i in iocs:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
    return {
        "total_iocs": len(iocs),
        "by_type": by_type,
        "by_source": {"otx": len(iocs)},
        "last_updated": "2026-07-05T03:00:07+00:00",
        "sources_configured": {"otx": True},
    }


@router.get("/api/threat-intel/summary")
def api_threat_summary():
    return _threat_summary()


@router.get("/api/threat-intel/iocs")
def api_threat_iocs(limit: int = 500, type: str = "", q: str = ""):
    cache = threat_intel.get_iocs(None, limit=limit)
    if cache:
        iocs = cache
    else:
        iocs = _otx_iocs()
    if type:
        iocs = [i for i in iocs if i.get("type") == type]
    if q:
        ql = q.lower()
        iocs = [i for i in iocs if ql in str(i.get("indicator", "")).lower()
                or ql in str(i.get("tags", "")).lower()]
    return {"iocs": iocs[:limit]}


@router.post("/api/threat-intel/update")
async def api_threat_update():
    try:
        return threat_intel.update_iocs()
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Rules ─────────────────────────────────────────────────────────────────

def _rule_out(r: dict) -> dict:
    return {
        "id": r.get("id", r.get("rule_id", "")),
        "name": r.get("name", "Rule"),
        "description": r.get("description", ""),
        "severity": ("critical" if r.get("level", 5) >= 12
                     else "high" if r.get("level", 5) >= 8
                     else "medium" if r.get("level", 5) >= 5 else "low"),
        "source": r.get("source", "builtin"),
        "enabled": r.get("enabled", r.get("status", "enabled") == "enabled"),
        "mitre_technique": r.get("mitre_technique", r.get("mitre", "")),
        "conditions": r.get("conditions", {}),
    }


@router.get("/api/rules")
def api_rules(q: str = ""):
    return {"rules": [_rule_out(r) for r in rule_engine.get_rules()]}


@router.post("/api/rules")
async def api_rules_create(request: Request):
    body = await request.json()
    rule = rule_engine.create_rule(body)
    return _rule_out(rule)


@router.put("/api/rules/{rule_id}")
async def api_rules_update(rule_id: str, request: Request):
    body = await request.json()
    rule = rule_engine.update_rule(rule_id, body)
    if rule is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return _rule_out(rule)


@router.delete("/api/rules/{rule_id}")
def api_rules_delete(rule_id: str):
    return {"success": rule_engine.delete_rule(rule_id)}


@router.post("/api/rules/{rule_id}/toggle")
async def api_rules_toggle(rule_id: str):
    rule = rule_engine.toggle_rule(rule_id)
    if rule is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return _rule_out(rule)


@router.post("/api/rules/test")
async def api_rules_test(request: Request):
    body = await request.json()
    return rule_engine.test_rule(body)


@router.get("/api/rules/export")
def api_rules_export():
    return rule_engine.export_rules()


@router.post("/api/rules/import/json")
async def api_rules_import_json(request: Request):
    raw = await request.body()
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return {"imported": 0, "error": "invalid JSON"}
    rules = data if isinstance(data, list) else data.get("rules", [])
    result = rule_engine.import_rules(rules, overwrite=False)
    return {"imported": result.get("imported", len(rules))}


@router.post("/api/rules/import/sigma")
@router.post("/api/rules/import/xml")
async def api_rules_import_text(request: Request):
    raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        result = rule_engine.import_rules([{"name": "sigma_import", "description": raw[:2000]}], overwrite=False)
        return {"imported": result.get("imported", 1)}
    except Exception:
        return {"imported": 0}


# ── Playbooks ─────────────────────────────────────────────────────────────

@router.get("/api/playbooks")
def api_playbooks():
    return {"playbooks": playbook_engine.get_playbooks()}


@router.get("/api/playbooks/actions")
def api_playbooks_actions():
    return {"actions": playbook_engine.AVAILABLE_ACTIONS}


@router.get("/api/playbooks/audit")
def api_playbooks_audit():
    return {"log": playbook_engine.get_audit_log(), "stats": playbook_engine.get_stats()}


@router.post("/api/playbooks")
async def api_playbooks_create(request: Request):
    body = await request.json()
    return playbook_engine.create_playbook(body)


@router.put("/api/playbooks/{pb_id}")
async def api_playbooks_update(pb_id: str, request: Request):
    body = await request.json()
    pb = playbook_engine.update_playbook(pb_id, body)
    if pb is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return pb


@router.delete("/api/playbooks/{pb_id}")
def api_playbooks_delete(pb_id: str):
    return {"success": playbook_engine.delete_playbook(pb_id)}


@router.post("/api/playbooks/{pb_id}/toggle")
async def api_playbooks_toggle(pb_id: str):
    pb = playbook_engine.toggle_playbook(pb_id)
    if pb is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return pb


# ── Reports ───────────────────────────────────────────────────────────────

@router.get("/api/reports")
def api_reports():
    return {"reports": report_generator.list_reports()}


@router.post("/api/reports/generate")
async def api_reports_generate():
    try:
        return report_generator.generate_report()
    except Exception as e:
        return JSONResponse({"error": {"message": str(e)}}, status_code=500)


@router.get("/api/reports/{report_id}/html")
def api_reports_html(report_id: str):
    html = report_generator.get_report_html(report_id)
    if html is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return HTMLResponse(html)


# ── Settings ──────────────────────────────────────────────────────────────

@router.get("/api/settings")
def api_settings():
    return settings_store.get_settings()


@router.put("/api/settings/integrations/{name}")
async def api_settings_integration(name: str, request: Request):
    body = await request.json()
    return settings_store.update_integration(name, body)


@router.get("/api/tools/virustotal/{hash_value}")
def api_virustotal(hash_value: str):
    try:
        result = settings_store.check_virustotal(hash_value.strip())
        if result is None:
            return {"error": "VirusTotal API key not configured"}
        return result
    except Exception as e:
        return {"error": str(e)}


# ── SOC Queue ─────────────────────────────────────────────────────────────

@router.get("/api/socqueue")
def api_socqueue():
    items = soc_queue.get_queue(None)
    for it in items:
        it["sla_pct"] = it.get("sla_pct", 0)
        it["sla_breached"] = it.get("sla_breached", False)
    return {"items": items}


@router.get("/api/socqueue/summary")
def api_socqueue_summary():
    items = soc_queue.get_queue(None)
    summary = _queue_summary(items)
    notes_count = 0
    try:
        f = BASE_DIR / "soc_queue_notes.json"
        if f.exists():
            data = json.loads(f.read_text())
            notes_count = sum(len(v) for v in data.values()) if isinstance(data, dict) else len(data)
    except Exception:
        pass
    summary["notes_count"] = notes_count
    return summary


@router.post("/api/socqueue/{item_id}/claim")
async def api_socqueue_claim(item_id: str, request: Request):
    body = await request.json()
    ok = soc_queue.claim_item(item_id, body.get("analyst", "analyst"))
    return {"success": ok}


@router.post("/api/socqueue/{item_id}/resolve")
async def api_socqueue_resolve(item_id: str, request: Request):
    ok = soc_queue.resolve_item(item_id, "resolved")
    return {"success": ok}


@router.post("/api/socqueue/{item_id}/escalate")
async def api_socqueue_escalate(item_id: str):
    ok = soc_queue.escalate_item(item_id)
    return {"success": ok}


@router.post("/api/socqueue/{item_id}/notes")
async def api_socqueue_notes(item_id: str, request: Request):
    body = await request.json()
    note = soc_queue.add_note(item_id, body.get("author", "analyst"), body.get("text", ""))
    return {"success": note is not None, "note": note}


# ── Platform ──────────────────────────────────────────────────────────────

@router.get("/api/platform/onboarding")
def api_platform_onboarding(org_id: str = "default"):
    tokens = platform_core.get_tokens()
    return {
        "instructions": {
            "steps": {
                "edr_agent": {
                    "linux": "curl -s http://173.208.232.91:8095/api/agent/download/windows -o agent.py && python3 agent.py --server 173.208.232.91:8095",
                    "manual": "Deploy agent_unified.py on the endpoint with --server 173.208.232.91:8095",
                },
                "siem_ingest": {
                    "http": "POST JSON events to http://173.208.232.91:8095/api/siem/ingest",
                    "syslog": "Configure SIEM_SYSLOG_PORT in mission-control-ui/.env to enable syslog ingestion",
                },
                "m365_itdr": {
                    "setup": "ITDR_* credentials configured in mission-control-ui/.env — run itdr_poller.poll_cycle() to ingest identity events",
                    "env": "ITDR_TENANT_ID, ITDR_CLIENT_ID, ITDR_CLIENT_SECRET",
                },
            },
        },
        "deploy_token": tokens[-1]["token"] if tokens else "",
    }


@router.post("/api/platform/tokens")
async def api_platform_tokens(request: Request):
    body = await request.json()
    tok = platform_core.create_token(org_id=body.get("org_id", "default"), label=body.get("label", ""))
    return tok


@router.get("/api/platform/orgs")
def api_platform_orgs():
    return {"organizations": platform_core.get_orgs()}


@router.post("/api/platform/orgs")
async def api_platform_orgs_create(request: Request):
    body = await request.json()
    return platform_core.create_org(body.get("name", "New Org"))


@router.delete("/api/platform/orgs/{org_id}")
def api_platform_orgs_delete(org_id: str):
    if org_id == "default":
        return {"success": False, "error": "default org cannot be deleted"}
    return {"success": platform_core.delete_org(org_id)}


@router.get("/api/platform/users")
def api_platform_users():
    return {"users": platform_core.get_users()}


@router.post("/api/platform/users")
async def api_platform_users_create(request: Request):
    body = await request.json()
    return platform_core.add_user(body.get("username", ""), body.get("role", "viewer"),
                                  body.get("org_id", "default"))


@router.patch("/api/platform/users/{user_id}/role")
async def api_platform_users_role(user_id: str, request: Request):
    body = await request.json()
    return {"success": platform_core.update_user_role(user_id, body.get("role", "viewer"))}


@router.get("/api/platform/roles")
def api_platform_roles():
    return {"roles": {k: {"name": v.get("name", k), "permissions": v.get("permissions", [])}
                      for k, v in platform_core.ROLES.items()}}


@router.get("/api/platform/webhooks")
def api_platform_webhooks():
    return {"webhooks": platform_core.get_webhooks()}


@router.post("/api/platform/webhooks")
async def api_platform_webhooks_create(request: Request):
    body = await request.json()
    return platform_core.register_webhook(body.get("url", ""), body.get("events", []))


@router.delete("/api/platform/webhooks/{wh_id}")
def api_platform_webhooks_delete(wh_id: str):
    return {"success": platform_core.delete_webhook(wh_id)}


# ── Autopilot (AI cases) ──────────────────────────────────────────────────

try:
    from ai_resolver import auto_resolve, create_case, list_cases, get_case, update_case, get_stats
except Exception:
    list_cases = get_case = update_case = get_stats = None


def _case_out(c: dict) -> dict:
    mitre = c.get("mitre_technique", c.get("mitre", "") or "")
    alert_ids = c.get("alert_ids", [])
    if isinstance(alert_ids, str):
        try:
            alert_ids = json.loads(alert_ids)
        except Exception:
            alert_ids = [alert_ids]
    events = c.get("events", [])
    if isinstance(events, str):
        try:
            events = json.loads(events)
        except Exception:
            events = []
    if not isinstance(events, list):
        events = []
    return {
        "id": c.get("id", ""),
        "title": c.get("title", "Case"),
        "severity": c.get("severity", "medium"),
        "status": c.get("status", "open"),
        "description": c.get("description", ""),
        "ai_analysis": c.get("ai_analysis", ""),
        "confidence": c.get("confidence", 0),
        "alert_count": len(alert_ids),
        "alert_ids": alert_ids,
        "mitre_technique": mitre,
        "mitre": {"technique_id": mitre, "technique": mitre},
        "events": [{"alert_id": e.get("alert_id", ""), "timestamp": e.get("timestamp", ""),
                    "type": e.get("type", "alert")} for e in events[:50]],
        "entities": c.get("entities", []) if isinstance(c.get("entities"), list) else [],
        "response_plan": c.get("response_plan", []),
        "created_at": c.get("created_at", c.get("ts", "")),
        "updated_at": c.get("updated_at", c.get("created_at", "")),
    }


@router.get("/api/autopilot/cases")
def api_autopilot_cases(limit: int = 100):
    if list_cases is None:
        return {"affected_items": []}
    cases = list_cases()[:limit]
    return {"affected_items": [_case_out(c) for c in cases]}


@router.get("/api/autopilot/stats")
def api_autopilot_stats():
    if get_stats is None:
        return {"last_24h": 0, "critical": 0, "high": 0, "resolved": 0, "avg_triage_time": 0}
    s = get_stats()
    return {
        "last_24h": s.get("last_24h", 0),
        "critical": s.get("critical", 0),
        "high": s.get("high", 0),
        "resolved": s.get("resolved", s.get("resolved_count", 0)),
        "avg_triage_time": s.get("avg_triage_time", 0),
    }


@router.get("/api/autopilot/trends")
def api_autopilot_trends():
    if list_cases is None:
        return {"days": []}
    cases = list_cases()
    days: dict[str, int] = {}
    for i in range(13, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        days[day] = 0
    for c in cases:
        ts = c.get("created_at", c.get("ts", ""))
        try:
            day = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).strftime("%Y-%m-%d")
            if day in days:
                days[day] += 1
        except Exception:
            continue
    return {"days": [{"date": d, "total": v} for d, v in days.items()]}


@router.get("/api/autopilot/cases/{case_id}")
def api_autopilot_case(case_id: str):
    if get_case is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    c = get_case(case_id)
    if c is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return _case_out(c)


@router.post("/api/autopilot/cases/{case_id}/approve")
async def api_autopilot_approve(case_id: str):
    c = get_case(case_id) if get_case else None
    if c:
        events = c.get("events", []) + [{
            "type": "approved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": "Approved by SOC operator",
        }]
        update_case(case_id, {"status": "approved", "events": events})
        return {"status": "ok", "case": {"id": case_id, "status": "approved"}}
    return {"status": "error", "message": "case not found", "case_id": case_id}


@router.post("/api/autopilot/cases/{case_id}/reject")
async def api_autopilot_reject(case_id: str):
    updated = update_case(case_id, {"status": "rejected"}) if update_case else None
    return {"status": "ok", "case": {"id": case_id, "status": "rejected" if updated else "unknown"}}
    # Note: suppression of similar alerts is handled by the AI autopilot scanner
    # (app.py's _add_suppression) — kept here as a plain reject for API parity.


@router.post("/api/autopilot/cases/{case_id}/execute")
async def api_autopilot_execute(case_id: str):
    """Execute a case's response plan in the background (Action Tier Engine).

    Human-gated: only approved cases execute. Tier-1 (reversible) actions are
    auto-executed at case creation; this endpoint runs the Tier-2 (major
    change) remainder after approval. Returns a dry-run preview of the planned
    actions with rollback guidance; the background task updates the case with
    the real results.
    """
    import threading
    from ai_remediate import classify_case, execute_case, rollback_notes, action_tier

    c = get_case(case_id) if get_case else None
    if not c:
        return {"status": "error", "message": "case not found", "case_id": case_id}
    if c.get("status") != "approved":
        return {"status": "error",
                "message": "case must be approved before execution",
                "case_id": case_id, "case_status": c.get("status")}

    tiers = classify_case(c)
    # Approved cases run the human-gated actions; all-Tier-1 plans run in full
    # (legacy cases created before the tier engine have no gated remainder).
    run_all = not tiers["tier2"]
    plan = tiers["tier2"] if tiers["tier2"] else tiers["tier1"]
    preview = [{
        "type": action if isinstance(action, str) else action.get("type", ""),
        "target": "" if isinstance(action, str) else action.get("target", action.get("value", "")),
        "tier": action_tier(action) if run_all else 2,
        "rollback": rollback_notes(action),
    } for action in plan]

    def _run():
        try:
            results = execute_case(c, tier=(None if run_all else 2))
            events = c.get("events", []) + [{
                "type": "executed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detail": "Executed %d action(s) after human approval" % len(results),
            }]
            update_case(case_id, {
                "status": "resolved" if results else "in_progress",
                "actions": results,
                "events": events,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            })
            logger.info("Case %s executed: %d action(s)", case_id, len(results))
        except Exception as e:  # noqa: BLE001 — report and fail the case visibly
            logger.error("Case %s execution failed: %s", case_id, e)
            update_case(case_id, {"status": "execution_failed"})

    threading.Thread(target=_run, daemon=True).start()
    return {
        "status": "ok",
        "message": "Execution triggered, running in background",
        "case_id": case_id,
        "plan": preview,
        "tier1_auto_executed": bool(tiers["tier1"]),
        "gated_actions": len(tiers["tier2"]),
    }


# ── Manager / Groups / Events (Wazuh-style synthesis) ─────────────────────

@router.get("/api/manager")
def api_manager():
    """Health of the SOC platform itself (not Wazuh daemons)."""
    import subprocess as _sp

    def svc(name: str) -> str:
        try:
            r = _sp.run(["systemctl", "-q", "is-active", name], capture_output=True, timeout=5)
            return "running" if r.returncode == 0 else "stopped"
        except Exception:
            return "unknown"

    agents = _agent_list()
    online_ids = _online_agent_ids()
    try:
        siem = siem_ingest.get_summary()
        siem_total = siem.get("total_logs", 0)
    except Exception:
        siem_total = 0
    try:
        itdr = itdr_poller.get_summary()
        itdr_total = itdr.get("total_events", 0)
    except Exception:
        itdr_total = 0
    return {"affected_items": [{
        "mission-soc": svc("mission-soc.service"),
        "mission-control-ui": "running",
        "edr-agent": svc("edr-agent.service"),
        "server-monitor": svc("server-monitor.service"),
        "wazuh-agentd": svc("wazuh-agent.service"),
        "name": "manager",
    }]}


@router.get("/api/manager/info")
def api_manager_info():
    return {"affected_items": [{
        "version": "1.1.0",
        "hostname": socket.gethostname(),
        "name": "soc-manager",
        "type": "SOC Platform",
        "cluster_status": "standalone",
        "node_name": "manager",
    }]}


@router.get("/api/groups")
def api_groups():
    agents = _agent_list()
    counts: dict[str, int] = {}
    for a in agents:
        g = a.get("platform", "unknown")
        counts[g] = counts.get(g, 0) + 1
    items = [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])] or [{"name": "default", "count": 0}]
    return {"affected_items": items}


@router.get("/api/events")
def api_events(size: int = 1, filters: str = ""):
    """Wazuh-style events query (AlertDetail page expects affected_items)."""
    alerts = []
    try:
        f = BASE_DIR / "ai_cases.json"
        if f.exists():
            cases = json.loads(f.read_text())
            for c in cases[:5]:
                alerts.append({
                    "id": c.get("id", ""),
                    "timestamp": c.get("created_at", c.get("ts", "")),
                    "rule": {"id": c.get("rule_id", ""), "level": c.get("level", 5),
                             "description": c.get("title", "")},
                    "agent": {"id": c.get("agent_id", ""), "name": c.get("agent_name", "")},
                    "location": c.get("source", ""),
                })
    except Exception:
        pass
    queue_items = soc_queue.get_queue(None)[:3]
    for it in queue_items:
        alerts.append({
            "id": it.get("id", ""),
            "timestamp": it.get("created_at", ""),
            "rule": {"id": "", "level": 5, "description": it.get("title", "")},
            "agent": {"id": "", "name": it.get("source", "")},
            "location": it.get("source", ""),
        })
    return {"affected_items": alerts[:max(1, size)]}


# ── AI chat (SSE) + NL search ─────────────────────────────────────────────

def _nl_answer(query: str) -> dict:
    """Local natural-language intent engine (fallback + SSE content source)."""
    q = query.lower()
    agents = _agent_list()
    online_ids = _online_agent_ids()
    siem = siem_ingest.get_summary()
    itdr = itdr_poller.get_summary()
    queue_items = soc_queue.get_queue(None)

    if any(w in q for w in ("overview", "summary", "status", "dashboard")):
        return {
            "intent": "overview",
            "message": ("Agents: %d total, %d online, %d offline. SIEM: %d logs. "
                        "ITDR: %d events. Queue: %d items.") % (
                len(agents), len(online_ids), max(0, len(agents) - len(online_ids)),
                siem.get("total_logs", 0), itdr.get("total_events", 0), len(queue_items)),
            "results": {"type": "overview",
                        "devices_total": len(agents), "devices_online": len(online_ids),
                        "devices_offline": max(0, len(agents) - len(online_ids)),
                        "alerts_open": len(queue_items), "agents_online": len(online_ids)},
        }
    if any(w in q for w in ("critical", "high", "alert")):
        crit = [i for i in queue_items if i.get("severity") in ("critical", "high")][:10]
        return {
            "intent": "critical_alerts",
            "message": f"{len(crit)} critical/high queue items.",
            "results": {"type": "critical_alerts", "count": len(crit),
                        "items": [{"severity": i.get("severity"), "title": i.get("title", ""),
                                   "site": i.get("source", "")} for i in crit]},
        }
    if any(w in q for w in ("agent", "device", "endpoint", "host")):
        off = [a for a in agents if a["id"] not in online_ids][:10]
        return {
            "intent": "offline_devices",
            "message": f"{len(off)} offline agents.",
            "results": {"type": "offline_devices", "count": len(off),
                        "items": [{"title": a["hostname"], "severity": "high",
                                   "site": a["platform"]} for a in off]},
        }
    return {"intent": "general",
            "message": "I can check SOC overview, critical alerts, and agent/endpoint status. Try 'overview', 'critical alerts', or 'agents'.",
            "results": {"type": "general", "items": []}}


@router.post("/api/nl/search")
async def api_nl_search(request: Request):
    body = await request.json()
    return _nl_answer(body.get("query", ""))


@router.post("/api/ai/chat")
async def api_ai_chat(request: Request):
    body = await request.json()
    query = body.get("query", "")
    answer = _nl_answer(query)

    async def stream():
        text = answer["message"]
        # Emit in small token chunks (client renders streaming text).
        words = text.split(" ")
        for i in range(0, len(words), 3):
            chunk = " ".join(words[i:i + 3])
            yield f"data: {json.dumps({'type': 'token', 'content': chunk + ' '})}\n\n"
            await asyncio.sleep(0.02)
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Remediation suggest (monitoring backend, graceful fallback) ───────────

@router.get("/remediation-api/remediation/suggest/{alert_id}")
def api_remediation_suggest(alert_id: str):
    # The real remediation engine lives behind the monitoring API (port 8000);
    # fall back to rule-based suggestions so the page never hard-fails.
    title = alert_id
    try:
        f = BASE_DIR / "ai_cases.json"
        if f.exists():
            for c in json.loads(f.read_text()):
                if c.get("id") == alert_id or alert_id in (c.get("alert_ids") or []):
                    title = c.get("title", alert_id)
                    break
    except Exception:
        pass
    return {
        "suggested_actions": [
            {"action": "Isolate host", "detail": "Contain the endpoint while investigating."},
            {"action": "Review logs", "detail": f"Correlate events for: {title[:120]}"},
            {"action": "Update detections", "detail": "Verify rules and IOCs match this alert."},
        ],
        "device": {"ip": "", "hostname": "", "device_type": "endpoint", "status": "UNKNOWN"},
    }


# ═══════════════════════════════════════════════════════
#  Legacy /wazuh-api/* aliases (old wazuh-soc.html)
#
# The legacy HTML page calls /mission/wazuh-api/* which previously proxied to
# the dead SOC API (208.87.135.185:5000).  These routes register BEFORE the
# proxy catch-all in app.py, so the old page now gets live data from the local
# SOC API.  Shapes match what wazuh-soc.html actually reads.
# ═══════════════════════════════════════════════════════

@router.get("/wazuh-api/overview")
def legacy_overview():
    agents = _agent_list()
    online = len(_online_agent_ids())
    vuln = vuln_store.get_vuln_summary() if hasattr(vuln_store, "get_vuln_summary") else vuln_store.get_summary()
    by_platform: dict[str, int] = {}
    for a in agents:
        by_platform[a["platform"]] = by_platform.get(a["platform"], 0) + 1
    try:
        import compliance_mapping as _cm
        scores = _cm.get_framework_scores()
        sca_score = int(round(scores.get("pci_dss", {}).get("overall_score", 50)))
    except Exception:
        sca_score = 50
    return {
        "total_agents": len(agents),
        "active": online,
        "offline": max(0, len(agents) - online),
        "never_connected": 0,
        "vulnerabilities": vuln.get("by_severity", {}),
        "sca_score": sca_score,
        "os_distribution": by_platform,
    }


@router.get("/wazuh-api/events/stats")
def legacy_events_stats():
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        f = BASE_DIR / "ai_cases.json"
        if f.exists():
            for c in json.loads(f.read_text()):
                s = str(c.get("severity", "low")).lower()
                key = {"critical": "Critical", "high": "High", "medium": "Medium"}.get(s, "Low")
                sev[key] += 1
    except Exception:
        pass
    queue_items = soc_queue.get_queue(None)
    for it in queue_items:
        s = str(it.get("severity", "low")).lower()
        key = {"critical": "Critical", "high": "High", "medium": "Medium"}.get(s, "Low")
        sev[key] += 1
    return {"severity": sev, "total": sum(sev.values())}


@router.get("/wazuh-api/events")
def legacy_events(size: int = 200, limit: int = 0):
    """Wazuh-style events window (alerts list on the legacy page)."""
    n = size if size > 0 else (limit or 200)
    items = []
    try:
        f = BASE_DIR / "ai_cases.json"
        if f.exists():
            for c in json.loads(f.read_text())[:n]:
                items.append({
                    "id": c.get("id", ""),
                    "timestamp": c.get("created_at", c.get("ts", "")),
                    "rule": {"id": c.get("rule_id", ""), "level": c.get("level", 5),
                             "description": c.get("title", "")},
                    "agent": {"id": c.get("agent_id", ""), "name": c.get("agent_name", "")},
                    "location": c.get("source", ""),
                })
    except Exception:
        pass
    if len(items) < n:
        for it in soc_queue.get_queue(None)[: n - len(items)]:
            items.append({
                "id": it.get("id", ""),
                "timestamp": it.get("created_at", ""),
                "rule": {"id": "", "level": 5, "description": it.get("title", "")},
                "agent": {"id": "", "name": it.get("source", "")},
                "location": it.get("source", ""),
            })
    return {"affected_items": items[:n]}


@router.get("/wazuh-api/agents")
def legacy_agents(limit: int = 500, select: str = ""):
    agents = _agent_list()[:limit]
    if select:
        fields = [f.strip() for f in select.split(",") if f.strip()]
        out = []
        for a in agents:
            row = {}
            for f in fields:
                if f == "os.platform":
                    row["os"] = {"platform": a.get("platform", "unknown")}
                else:
                    row[f] = a.get(f)
            out.append(row)
        return {"affected_items": out}
    return {"affected_items": [{"id": a["id"], "name": a["name"], "ip": a["ip"],
                                "os": {"platform": a["platform"]}, "status": a["status"],
                                "version": a["version"], "lastKeepAlive": a["last_seen"]}
                               for a in agents]}


@router.get("/wazuh-api/overview/sca")
def legacy_overview_sca():
    return {"affected_items": []}


@router.get("/wazuh-api/overview/fim")
def legacy_overview_fim():
    events = fim_store.get_events(filters=None, limit=100)
    items = [{"agent_id": e.get("agent", ""), "file": e.get("path", ""),
              "type": e.get("action", "modified"), "date": e.get("ts", e.get("timestamp", ""))}
             for e in events]
    return {"affected_items": items}


@router.get("/wazuh-api/overview/vulnerabilities")
def legacy_overview_vuln():
    findings = vuln_store.get_findings(severity="", )
    items = [{"severity": f.get("severity", "low"), "cve": f.get("cve", f.get("cve_id", "")),
              "agent_id": f.get("agent_id", f.get("agent", "")),
              "name": f.get("package", f.get("package_name", "")),
              "version": f.get("version", f.get("package_version", ""))} for f in findings]
    return {"affected_items": items}


@router.get("/wazuh-api/mitre")
def legacy_mitre():
    techniques = mitre_mapping.get_mitre_techniques()
    items = techniques.get("techniques", []) if isinstance(techniques, dict) else techniques
    return {"affected_items": [
        {"id": t.get("id", ""), "technique": t.get("id", ""), "description": t.get("description", ""),
         "score": min(100, (t.get("count", 0) or 0) * 20)} for t in items]}


@router.get("/wazuh-api/rules")
def legacy_rules(limit: int = 50):
    rules = rule_engine.get_rules()[:limit]
    items = []
    for r in rules:
        lvl = r.get("level", 5)
        items.append({
            "id": r.get("rule_id", r.get("id", 0)),
            "level": lvl,
            "description": r.get("name", "Rule"),
            "groups": r.get("groups", []) if isinstance(r.get("groups"), list) else [],
        })
    return {"affected_items": items}


@router.get("/wazuh-api/decoders")
def legacy_decoders(limit: int = 50):
    return {"affected_items": []}


@router.get("/wazuh-api/otx/status")
def legacy_otx_status():
    try:
        if _OTX_FILE.exists():
            d = json.loads(_OTX_FILE.read_text())
            return {"enabled": d.get("enabled", True), "total_iocs": d.get("total_iocs", 0),
                    "pulse_count": d.get("pulse_count", 0), "last_updated": d.get("last_updated", ""),
                    "message": d.get("message", "")}
    except Exception:
        pass
    return {"enabled": False, "total_iocs": 0}


@router.get("/wazuh-api/otx/iocs")
def legacy_otx_iocs(type: str = "", q: str = ""):
    iocs = _otx_iocs()
    if type:
        iocs = [i for i in iocs if i.get("type", "").lower() == type.lower()]
    if q:
        ql = q.lower()
        iocs = [i for i in iocs if ql in str(i.get("indicator", "")).lower()]
    return {"total": len(iocs), "iocs": iocs}


@router.post("/wazuh-api/otx/refresh")
async def legacy_otx_refresh():
    try:
        result = threat_intel.update_iocs()
        return result if isinstance(result, dict) else {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/wazuh-api/otx/download")
def legacy_otx_download():
    rules_path = BASE_DIR / "otx_rules.xml"
    if rules_path.exists():
        return Response(content=rules_path.read_bytes(), media_type="application/xml",
                        headers={"Content-Disposition": "attachment; filename=otx_rules.xml"})
    return JSONResponse({"error": "rules file not found"}, status_code=404)