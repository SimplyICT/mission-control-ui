#!/usr/bin/env python3
"""Unified Cross-Platform Agent — Windows, macOS, Linux.

Connects to SOC server via WebSocket, reports telemetry, accepts commands.

Architecture:
    Agent                          SOC Server
    ─────                          ──────────
    WebSocket connect ───────────▶ /api/agent/ws
    Register (hostname, os, ver) ─▶
    Telemetry every 60s ──────────▶ processes, network, system info
    ◀─── Command: kill, isolate, quarantine
    Result ──────────────────────▶

Packaging:
    Windows: PyInstaller → .exe + nssm → Windows Service
    macOS:   .app bundle + LaunchDaemon plist
    Linux:   systemd service (already done)
"""
import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import platform
import py_compile
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s agent %(message)s")
logger = logging.getLogger("agent")

AGENT_VERSION = "1.1.9"
RECONNECT_BASE = 5
HEARTBEAT_INTERVAL = 30
TELEMETRY_INTERVAL = 60

# Response-action limits. The server never sees more than these; a fetch that
# would exceed the hard cap is refused rather than silently truncated, because
# a truncated artifact is worse evidence than a clear refusal.
FETCH_DEFAULT_BYTES = 1024 * 1024
FETCH_HARD_BYTES = 2 * 1024 * 1024
SCRIPT_MAX_BYTES = 64 * 1024
SCRIPT_DEFAULT_TIMEOUT = 60
SCRIPT_MAX_TIMEOUT = 300
OUTPUT_TAIL = 4000

# Isolation is applied through one named iptables chain so release can remove
# exactly what isolate added, even if the chain is re-applied between the two.
ISOLATION_CHAIN = "SOC_ISOLATE"
ISOLATION_RULE_PREFIX = "SOC_ISOLATE_"
WINDOWS_ISOLATION_ALLOW_IN = ISOLATION_RULE_PREFIX + "ALLOW_COLLECTOR_IN"
WINDOWS_ISOLATION_ALLOW_OUT = ISOLATION_RULE_PREFIX + "ALLOW_COLLECTOR_OUT"
WINDOWS_ISOLATION_BLOCK_IN = ISOLATION_RULE_PREFIX + "BLOCK_IN"
WINDOWS_ISOLATION_BLOCK_OUT = ISOLATION_RULE_PREFIX + "BLOCK_OUT"

_agent_id = None

# Collector address, learned from --server. isolate() needs it to keep the
# control channel open while everything else is blocked.
_collector = {"host": "", "port": 0}


# ═══════════════════════════════════════════════════════
#  Platform Detection
# ═══════════════════════════════════════════════════════

def get_platform() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    return system


def get_hostname() -> str:
    try:
        return platform.node() or socket.gethostname()
    except:
        return os.environ.get("COMPUTERNAME", "unknown")


import socket


# ═══════════════════════════════════════════════════════
#  Telemetry Collectors (cross-platform)
# ═══════════════════════════════════════════════════════

def collect_system_info() -> dict:
    """Basic system info — works on all platforms."""
    return {
        "hostname": get_hostname(),
        "platform": get_platform(),
        "os_name": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "agent_version": AGENT_VERSION,
        "build": "exe" if getattr(sys, "frozen", False) else "script",
        "boot_time": _get_boot_time(),
        "cpu_count": os.cpu_count() or 0,
    }


def _get_boot_time() -> str:
    try:
        if get_platform() == "windows":
            r = subprocess.run(["wmic", "os", "get", "lastbootuptime"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                return r.stdout.strip().split("\n")[-1].strip()[:14]
        elif get_platform() == "linux":
            r = subprocess.run(["uptime", "-s"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout.strip()
        elif get_platform() == "macos":
            r = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout.strip()
    except: pass
    return ""


def collect_processes(limit: int = 100) -> list[dict]:
    """Cross-platform process list."""
    processes = []
    plat = get_platform()

    try:
        if plat == "windows":
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n")[:limit]:
                    parts = line.strip('"').split('","')
                    if len(parts) >= 5:
                        processes.append({
                            "pid": parts[1] if len(parts) > 1 else "?",
                            "name": parts[0],
                            "session": parts[2] if len(parts) > 2 else "",
                            "mem": parts[4] if len(parts) > 4 else "",
                        })
        else:
            # Linux/macOS
            r = subprocess.run(
                ["ps", "aux", "--sort=-%cpu"] if plat == "linux" else ["ps", "aux"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                lines = r.stdout.strip().split("\n")[1:1+limit]
                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            "pid": parts[1],
                            "user": parts[0],
                            "cpu": parts[2],
                            "mem": parts[3],
                            "command": parts[10][:100],
                        })
    except Exception as e:
        logger.warning("Process collection failed: %s", e)

    return processes


def collect_network() -> list[dict]:
    """Cross-platform network connections."""
    connections = []
    plat = get_platform()

    try:
        if plat == "windows":
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 4 and (parts[0].startswith("TCP") or parts[0].startswith("UDP")):
                        connections.append({
                            "protocol": parts[0],
                            "local": parts[1],
                            "peer": parts[2],
                            "state": parts[3] if len(parts) > 3 else "",
                            "pid": parts[4] if len(parts) > 4 else "",
                        })
        else:
            r = subprocess.run(
                ["ss", "-tunap"] if plat == "linux" else ["lsof", "-i"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                lines = r.stdout.strip().split("\n")[1:80]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        connections.append({
                            "protocol": parts[0],
                            "local": parts[4] if len(parts) > 4 else "",
                            "peer": parts[5] if len(parts) > 5 else "",
                            "state": parts[1] if parts[0] == "tcp" else "",
                        })
    except Exception as e:
        logger.warning("Network collection failed: %s", e)

    return connections


def collect_disks() -> list[dict]:
    """Cross-platform disk usage."""
    disks = []
    plat = get_platform()
    try:
        if plat == "windows":
            r = subprocess.run(["wmic", "logicaldisk", "get", "size,freespace,caption"],
                             capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        disks.append({"drive": parts[0], "free": parts[1], "size": parts[2]})
        else:
            r = subprocess.run(["df", "-h", "--output=source,size,used,avail,pcent"],
                             capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        disks.append({"mount": parts[0], "size": parts[1], "used": parts[2], "avail": parts[3], "pct": parts[4]})
    except: pass
    return disks


# ═══════════════════════════════════════════════════════
#  Command Handlers
# ═══════════════════════════════════════════════════════


HANDLERS = {}
def handler(name: str):
    def wrap(f):
        HANDLERS[name] = f
        return f
    return wrap


@handler("ping")
async def cmd_ping(args: dict) -> dict:
    return {"success": True, "message": "pong", "agent_version": AGENT_VERSION}


@handler("collect")
async def cmd_collect(args: dict) -> dict:
    return {
        "success": True,
        "system": collect_system_info(),
        "processes": collect_processes(args.get("limit", 50)),
        "network": collect_network(),
        "disks": collect_disks(),
    }


@handler("processes")
async def cmd_processes(args: dict) -> dict:
    return {"success": True, "count": 0, "processes": collect_processes(args.get("limit", 100))}


@handler("network")
async def cmd_network(args: dict) -> dict:
    return {"success": True, "count": 0, "connections": collect_network()}


@handler("system")
async def cmd_system(args: dict) -> dict:
    return {"success": True, **collect_system_info()}


@handler("kill")
async def cmd_kill(args: dict) -> dict:
    pid = args.get("pid", "")
    signal = args.get("signal", "TERM")
    plat = get_platform()
    try:
        if plat == "windows":
            r = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True, timeout=10)
        else:
            r = subprocess.run(["kill", f"-{signal}", str(pid)], capture_output=True, text=True, timeout=10)
        return {"success": r.returncode == 0, "pid": pid, "detail": r.stderr.strip() or "ok"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════
#  Isolation helpers
# ═══════════════════════════════════════════════════════

def _set_collector(server: str) -> None:
    """Remember the collector we are connected to (host[,port])."""
    host, _, port = str(server or "").partition(":")
    _collector["host"] = host.strip()
    _collector["port"] = int(port) if port.strip().isdigit() else 0


def _collector_ip() -> str:
    """Collector host as a literal IP — firewall rules cannot take a hostname."""
    host = str(_collector.get("host") or "").strip()
    if not host:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    try:
        info = socket.getaddrinfo(host, _collector.get("port") or None, proto=socket.IPPROTO_TCP)
        return info[0][4][0] if info else ""
    except Exception:
        return ""


def _isolation_state_file() -> str:
    for base in (os.path.expanduser("~"), os.path.dirname(_agent_script_path())):
        if base and os.path.isdir(base):
            return os.path.join(base, ".soc-agent-isolation.json")
    return ".soc-agent-isolation.json"


def _save_isolation_state(fields: dict) -> None:
    try:
        with open(_isolation_state_file(), "w", encoding="utf-8") as f:
            json.dump(fields, f, indent=2)
    except Exception as e:
        logger.warning("Could not record isolation state: %s", e)


def _clear_isolation_state() -> None:
    try:
        os.remove(_isolation_state_file())
    except Exception:
        pass


def _linux_isolation_rules(collector_ip: str, collector_port: int) -> list[list[str]]:
    """iptables argv for isolation, in apply order.

    iptables is first-match-wins, so every ACCEPT has to sit above the terminal
    DROP: an allow rule appended after the DROP is dead code and would silently
    lock the collector out, leaving no remote way to release the host.
    """
    chain = ISOLATION_CHAIN
    rules = [
        ["iptables", "-N", chain],
        ["iptables", "-F", chain],
        # Loopback is host-local IPC, not egress; dropping it breaks the agent's
        # own health checks without isolating anything.
        ["iptables", "-A", chain, "-i", "lo", "-j", "ACCEPT"],
    ]
    if collector_ip:
        # Replies for the live collector session, both directions, before the
        # port rules so an already-open control channel survives a port change
        # on the collector side.
        rules += [
            ["iptables", "-A", chain, "-s", collector_ip,
             "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["iptables", "-A", chain, "-d", collector_ip,
             "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
        if collector_port:
            rules += [
                ["iptables", "-A", chain, "-s", collector_ip, "-p", "tcp",
                 "--sport", str(collector_port), "-j", "ACCEPT"],
                ["iptables", "-A", chain, "-d", collector_ip, "-p", "tcp",
                 "--dport", str(collector_port), "-j", "ACCEPT"],
            ]
    else:
        # Unresolved collector: keeping established flows is the only safe
        # default. A hard drop with no allow rule would strand a host that can
        # only be released over the network.
        rules.append(["iptables", "-A", chain,
                      "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    rules.append(["iptables", "-A", chain, "-j", "DROP"])
    # -I 1 (insert at the top), not -A: a permissive ACCEPT already present in
    # INPUT/OUTPUT must not be reached before the isolation chain.
    rules += [
        ["iptables", "-I", "INPUT", "1", "-j", chain],
        ["iptables", "-I", "OUTPUT", "1", "-j", chain],
    ]
    return rules


def _windows_isolation_rules(collector_ip: str, collector_port: int) -> list[list[str]]:
    """netsh argv for isolation, in apply order.

    Allow rules are added first as required, but ordering alone does NOT keep
    the collector reachable on Windows: Windows Firewall evaluates block rules
    before allow rules regardless of creation order. The block rules therefore
    carry a remoteip exclusion for the collector, which is what actually leaves
    the control channel open.
    """
    rules = []
    if collector_ip:
        allow_in = ["netsh", "advfirewall", "firewall", "add", "rule",
                    "name=" + WINDOWS_ISOLATION_ALLOW_IN, "dir=in", "action=allow",
                    "protocol=TCP", "remoteip=" + collector_ip]
        allow_out = ["netsh", "advfirewall", "firewall", "add", "rule",
                     "name=" + WINDOWS_ISOLATION_ALLOW_OUT, "dir=out", "action=allow",
                     "protocol=TCP", "remoteip=" + collector_ip]
        if collector_port:
            allow_in.append("localport=" + str(collector_port))
            allow_out.append("remoteport=" + str(collector_port))
        rules += [allow_in, allow_out]
        blocked = "remoteip=!" + collector_ip
    else:
        blocked = ""
    for name, direction in ((WINDOWS_ISOLATION_BLOCK_IN, "in"),
                            (WINDOWS_ISOLATION_BLOCK_OUT, "out")):
        block = ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=" + name, "dir=" + direction, "action=block"]
        if blocked:
            block.append(blocked)
        rules.append(block)
    return rules


def _apply_isolation_windows(rules: list[list[str]]) -> dict:
    # Legacy rules would otherwise survive release and keep the host blocked.
    _legacy_windows_isolation_cleanup()
    for argv in rules:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            # Never leave a half-applied ruleset behind: drop whatever landed
            # and report the failure so the analyst can retry cleanly.
            _release_isolation_windows()
            return {"success": False, "error": (r.stderr or r.stdout).strip() or " ".join(argv)}
    return {"success": True, "detail": "isolated (both directions blocked except collector)"}


def _apply_isolation_linux(rules: list[list[str]]) -> dict:
    # Isolate is idempotent: drop the jumps an earlier isolate left behind first,
    # otherwise repeated calls stack duplicate jumps in INPUT/OUTPUT. Failures
    # are expected when nothing is isolated yet.
    for target in ("INPUT", "OUTPUT"):
        subprocess.run(["iptables", "-D", target, "-j", ISOLATION_CHAIN],
                       capture_output=True, text=True, timeout=20)
    applied = []
    for argv in rules:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        msg = (r.stderr or r.stdout).strip()
        if r.returncode != 0:
            # -N fails when the chain already exists; -F, the rule adds and the
            # jump inserts failing is a real problem.
            if argv[1] == "-N" and "exist" in msg.lower():
                continue
            if argv[1] == "-F" and "no chain" in msg.lower():
                continue
            for undo in reversed(applied):
                subprocess.run(undo, capture_output=True, text=True, timeout=20)
            return {"success": False, "error": msg or " ".join(argv)}
        applied.append(_linux_undo(argv))
    return {"success": True, "detail": "isolated (both directions blocked except collector)"}


def _linux_undo(argv: list[str]) -> list[str]:
    """Inverse of one applied iptables argv, for rollback.

    Rollback runs in reverse apply order, so the chain is flushed by -F's undo
    before -N's undo tries to delete it.
    """
    if len(argv) > 1 and argv[1] == "-I":
        return ["iptables", "-D", argv[2], "-j", argv[-1]]
    if len(argv) > 2 and argv[1] == "-A":
        return ["iptables", "-D"] + argv[2:]
    if len(argv) > 1 and argv[1] == "-N":
        return ["iptables", "-X", ISOLATION_CHAIN]
    return ["iptables", "-F", ISOLATION_CHAIN]


def _legacy_windows_isolation_cleanup() -> None:
    """Delete the pre-1.1.9 inbound block rule.

    Older builds isolated with a single EDR_ISOLATE rule and a later release
    only removed that same name; leaving it behind would keep an isolated host
    blocked with no command able to clear it.
    """
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR_ISOLATE"],
                   capture_output=True, text=True, timeout=20)


def _release_isolation_windows() -> dict:
    """Delete every rule isolate may have added. Idempotent."""
    names = [WINDOWS_ISOLATION_ALLOW_IN, WINDOWS_ISOLATION_ALLOW_OUT,
             WINDOWS_ISOLATION_BLOCK_IN, WINDOWS_ISOLATION_BLOCK_OUT]
    missing = []
    for name in names:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=" + name],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode != 0:
            missing.append(name)
    _legacy_windows_isolation_cleanup()
    if len(missing) == len(names):
        return {"success": True, "detail": "not isolated"}
    return {"success": True, "detail": "released"}


def _release_isolation_linux() -> dict:
    """Remove exactly what isolate added: the jumps, then the chain. Idempotent."""
    chain = ISOLATION_CHAIN
    existed = subprocess.run(["iptables", "-n", "-L", chain],
                             capture_output=True, text=True, timeout=20).returncode == 0
    for target in ("INPUT", "OUTPUT"):
        # Loop: isolate is idempotent but an older build could have inserted the
        # jump more than once; delete every copy.
        for _ in range(10):
            if subprocess.run(["iptables", "-D", target, "-j", chain],
                              capture_output=True, text=True, timeout=20).returncode != 0:
                break
    if existed:
        subprocess.run(["iptables", "-F", chain], capture_output=True, text=True, timeout=20)
        subprocess.run(["iptables", "-X", chain], capture_output=True, text=True, timeout=20)
    return {"success": True, "detail": "released" if existed else "not isolated"}


@handler("isolate")
async def cmd_isolate(args: dict) -> dict:
    """Isolate the host: block both directions, keep the collector reachable."""
    plat = get_platform()
    try:
        if plat == "windows":
            rules = _windows_isolation_rules(_collector_ip(), _collector["port"])
            result = _apply_isolation_windows(rules)
        elif plat == "linux":
            rules = _linux_isolation_rules(_collector_ip(), _collector["port"])
            result = _apply_isolation_linux(rules)
        else:
            return {"success": False, "error": f"isolation is not supported on {plat}"}
        if result.get("success"):
            _save_isolation_state({
                "isolated_at": datetime.now(timezone.utc).isoformat(),
                "platform": plat,
                "collector_ip": _collector_ip(),
                "collector_port": _collector["port"],
            })
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


@handler("release")
async def cmd_release(args: dict) -> dict:
    """Release the host: remove exactly the rules isolate added."""
    plat = get_platform()
    try:
        if plat == "windows":
            result = _release_isolation_windows()
        elif plat == "linux":
            result = _release_isolation_linux()
        else:
            return {"success": False, "error": f"isolation is not supported on {plat}"}
        if result.get("success"):
            _clear_isolation_state()
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════
#  Response actions: quarantine, fetch, service, run_script
# ═══════════════════════════════════════════════════════

SERVICE_ACTIONS = ("start", "stop", "restart", "disable", "enable", "status")


def _quarantine_dir() -> str:
    """Quarantine root for this platform."""
    override = os.environ.get("SOC_AGENT_QUARANTINE_DIR")
    if override:
        return override
    if get_platform() == "windows":
        # %ProgramData% is the documented system-wide location; the literal
        # fallback covers service environments with a stripped environment block.
        base = os.environ.get("ProgramData") or r"C:\ProgramData"
        return os.path.join(base, "SOCAgent", "quarantine")
    return "/var/lib/soc-agent/quarantine"


def _resolve_path(value) -> str:
    raw = str(value or "").strip()
    return os.path.abspath(os.path.expanduser(raw)) if raw else ""


def _sha256_file(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


@handler("quarantine")
async def cmd_quarantine(args: dict) -> dict:
    """Move a file into quarantine, hashing it before it leaves the scene."""
    path = _resolve_path(args.get("path"))
    if not path:
        return {"success": False, "error": "path required"}
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    try:
        # Hash first: once the file is moved the evidence must still carry the
        # digest of the bytes as they were found.
        sha256, size = _sha256_file(path)
        qdir = _quarantine_dir()
        os.makedirs(qdir, mode=0o700, exist_ok=True)
        dest = os.path.join(qdir, f"{sha256[:12]}_{os.path.basename(path)}")
        if os.path.exists(dest):
            # Collision on digest+name means different bytes; keep both rather
            # than overwrite the earlier evidence copy.
            dest = os.path.join(qdir, f"{sha256[:12]}_{int(time.time())}_{os.path.basename(path)}")
        shutil.move(path, dest)
        if os.path.exists(path):
            return {"success": False, "error": f"failed to move {path} to {dest}"}
        with open(dest + ".json", "w", encoding="utf-8") as f:
            json.dump({
                "original_path": path,
                "quarantined_to": dest,
                "sha256": sha256,
                "size": size,
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2)
        return {"success": True, "quarantined_to": dest, "sha256": sha256, "size": size}
    except Exception as e:
        return {"success": False, "error": str(e)}


@handler("fetch")
async def cmd_fetch(args: dict) -> dict:
    """Return a file's bytes (base64) for the case, bounded by a byte cap."""
    path = _resolve_path(args.get("path"))
    if not path:
        return {"success": False, "error": "path required"}
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    try:
        max_bytes = int(args.get("max_bytes") or FETCH_DEFAULT_BYTES)
    except (TypeError, ValueError):
        return {"success": False, "error": "max_bytes must be an integer"}
    if max_bytes <= 0:
        return {"success": False, "error": "max_bytes must be positive"}
    if max_bytes > FETCH_HARD_BYTES:
        return {"success": False, "error": f"max_bytes exceeds hard cap {FETCH_HARD_BYTES}"}
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return {"success": False,
                    "error": f"file is {size} bytes, over the {max_bytes} byte cap"}
        # Read one byte past the cap so a file that grows between stat and read
        # is refused instead of silently truncated.
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
        if len(data) > max_bytes:
            return {"success": False, "error": f"file grew past the {max_bytes} byte cap"}
        return {
            "success": True,
            "name": os.path.basename(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "content_b64": base64.b64encode(data).decode("ascii"),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _windows_service_commands(name: str, action: str) -> list[list[str]]:
    sc = "sc.exe"
    if action == "start":
        return [[sc, "start", name]]
    if action == "stop":
        return [[sc, "stop", name]]
    if action == "restart":
        # sc.exe reports an already-stopped service as an error; the start that
        # follows is what decides whether the restart worked.
        return [[sc, "stop", name], [sc, "start", name]]
    if action == "disable":
        return [[sc, "config", name, "start=", "disabled"]]
    if action == "enable":
        return [[sc, "config", name, "start=", "auto"]]
    return [[sc, "query", name]]


def _service_windows(name: str, action: str) -> dict:
    chunks = []
    ok = True
    for argv in _windows_service_commands(name, action):
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        chunks.append((r.stdout or r.stderr).strip())
        if r.returncode != 0 and not (action == "restart" and argv[1] == "stop"):
            ok = False
            break
    return {"success": ok, "detail": " | ".join(c for c in chunks if c) or "ok"}


@handler("service")
async def cmd_service(args: dict) -> dict:
    """Start/stop/restart/enable/disable/query a service."""
    name = str(args.get("name") or "").strip()
    action = str(args.get("action") or "").strip().lower()
    if not name:
        return {"success": False, "error": "name required", "detail": ""}
    if action not in SERVICE_ACTIONS:
        return {"success": False, "error": f"unsupported action: {action}", "detail": ""}
    try:
        if get_platform() == "windows":
            return _service_windows(name, action)
        # argv list, never a shell string: a hostile service name must not be
        # able to become a second command.
        r = subprocess.run(["systemctl", action, name],
                           capture_output=True, text=True, timeout=60)
        return {"success": r.returncode == 0,
                "detail": (r.stderr or r.stdout).strip() or "ok"}
    except Exception as e:
        return {"success": False, "error": str(e), "detail": str(e)}


SCRIPT_INTERPRETERS = {
    "powershell": (["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"], ".ps1"),
    "pwsh": (["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"], ".ps1"),
    "cmd": (["/c"], ".bat"),
    "sh": ([], ".sh"),
    "bash": ([], ".sh"),
}


def _script_command(alias: str, script_path: str, extra: list[str]) -> tuple[list[str], str]:
    """Build (argv, file encoding) for one interpreter. Raises ValueError if unusable."""
    plat = get_platform()
    if alias in ("sh", "bash"):
        if plat == "windows":
            raise ValueError(f"interpreter {alias!r} is not available on Windows")
        return ["/bin/" + alias, script_path] + extra, "utf-8"
    if alias == "cmd":
        if plat != "windows":
            raise ValueError("interpreter 'cmd' is only available on Windows")
        return ["cmd"] + SCRIPT_INTERPRETERS["cmd"][0] + [script_path] + extra, "utf-8"
    if alias in ("powershell", "pwsh"):
        static, _ = SCRIPT_INTERPRETERS[alias]
        if plat == "windows":
            program = "powershell" if alias == "powershell" else "pwsh"
        else:
            program = shutil.which(alias) or ""
            if not program:
                raise ValueError(f"interpreter {alias!r} is not installed")
        # utf-8-sig on purpose: Windows PowerShell 5.1 reads a BOM-less file as
        # ANSI and mangles any non-ASCII byte the analyst sent.
        return [program] + static + [script_path] + extra, "utf-8-sig"
    raise ValueError(f"unsupported interpreter: {alias}")


def _script_spawn_flags() -> dict:
    """POSIX: put the script in its own process group so a timeout can kill
    everything it spawned, not just the shell it started."""
    return {"start_new_session": True} if os.name == "posix" else {}


def _kill_script(proc) -> None:
    """Kill the script and its children."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            # Windows has no process groups; taskkill /T is the tree kill.
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


@handler("run_script")
async def cmd_run_script(args: dict) -> dict:
    """Run an analyst-supplied script with bounded size, time and output."""
    if args.get("confirm") is not True:
        return {"success": False, "error": "confirm must be true"}
    script = args.get("script")
    if not isinstance(script, str) or not script.strip():
        return {"success": False, "error": "script required"}
    if len(script.encode("utf-8")) > SCRIPT_MAX_BYTES:
        return {"success": False, "error": f"script exceeds {SCRIPT_MAX_BYTES} bytes"}
    try:
        timeout = int(args.get("timeout_secs") or SCRIPT_DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        return {"success": False, "error": "timeout_secs must be an integer"}
    if timeout <= 0:
        return {"success": False, "error": "timeout_secs must be positive"}
    timeout = min(timeout, SCRIPT_MAX_TIMEOUT)

    raw_args = args.get("args")
    if raw_args is None:
        extra = []
    elif isinstance(raw_args, list):
        extra = [str(a) for a in raw_args]
    elif isinstance(raw_args, str):
        extra = shlex.split(raw_args)
    else:
        return {"success": False, "error": "args must be a list or string"}

    plat = get_platform()
    alias = str(args.get("interpreter") or "").strip().lower()
    if not alias:
        alias = "powershell" if plat == "windows" else "sh"
    suffix = SCRIPT_INTERPRETERS.get(alias, ([], ".sh"))[1]

    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="soc-agent-run-")
        script_path = os.path.join(tmpdir, "task" + suffix)
        argv, encoding = _script_command(alias, script_path, extra)
        with open(script_path, "w", encoding=encoding) as f:
            f.write(script)
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=tmpdir, **_script_spawn_flags(),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        # Shield the reader from the timeout: cancelling communicate() leaves
        # the transport unable to see pipe EOF, so wait() would then block for
        # the script's full lifetime instead of the requested timeout.
        reader = asyncio.ensure_future(proc.communicate())
        try:
            out, err = await asyncio.wait_for(asyncio.shield(reader), timeout=timeout)
        except asyncio.TimeoutError:
            _kill_script(proc)
            try:
                # Drain what the script managed to write before the kill.
                out, err = await asyncio.wait_for(reader, timeout=10)
            except Exception:
                out, err = b"", b""
            return {"success": False, "error": f"timeout after {timeout}s", "exit_code": -1,
                    "stdout_tail": out.decode("utf-8", "replace")[-OUTPUT_TAIL:],
                    "stderr_tail": err.decode("utf-8", "replace")[-OUTPUT_TAIL:]}
        code = proc.returncode if proc.returncode is not None else -1
        return {
            "success": code == 0,
            "exit_code": code,
            "stdout_tail": out.decode("utf-8", "replace")[-OUTPUT_TAIL:],
            "stderr_tail": err.decode("utf-8", "replace")[-OUTPUT_TAIL:],
        }
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        # The script is one-shot evidence collection; never leave the temp copy
        # on disk, even when the run failed or timed out.
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════
#  HTTP Polling Fallback (when aiohttp not available)
# ═══════════════════════════════════════════════════════

async def _polling_mode(server: str):
    """HTTP polling mode — polls the server for commands every 30s.
    Used when aiohttp is not available (e.g., macOS without pip).
    """
    _set_collector(server)
    import urllib.request as _ur
    import json as _json
    import uuid as _uuid
    
    agent_id = str(_uuid.uuid4())[:8]
    hostname = get_hostname()
    plat = get_platform()
    poll_url = f"http://{server}/api/agent/{agent_id}/poll"
    result_url = f"http://{server}/api/agent/{agent_id}/result"
    
    logger.info("Polling mode started (%s)", poll_url)
    
    while True:
        try:
            # Register / heartbeat
            info = collect_system_info()
            info["agent_id"] = agent_id
            info["hostname"] = hostname
            data = _json.dumps({"type": "register", "data": info}).encode()
            req = _ur.Request(poll_url, data=data, headers={"Content-Type": "application/json"})
            resp = _ur.urlopen(req, timeout=15)
            body = resp.read().decode()
            
            # Process any pending commands
            if body:
                try:
                    cmd_data = _json.loads(body)
                    cmd = cmd_data.get("command", "")
                    args = cmd_data.get("args", {})
                    cmd_id = cmd_data.get("id", "")
                    
                    handler_fn = HANDLERS.get(cmd)
                    if handler_fn:
                        result = await handler_fn(args)
                        result_data = _json.dumps({
                            "type": "result", "id": cmd_id,
                            "command": cmd, "result": result,
                        }).encode()
                        req2 = _ur.Request(result_url, data=result_data,
                            headers={"Content-Type": "application/json"})
                        _ur.urlopen(req2, timeout=15)
                    elif cmd_data.get("needs_update"):
                        # Poll doubles as the version check for agents without a WS.
                        logger.info("Auto-update offered: %s -> %s", AGENT_VERSION,
                                    cmd_data.get("latest_version", "?"))
                        await perform_self_update(
                            download_url=cmd_data.get("download_url", ""),
                            expected_sha=cmd_data.get("agent_sha256", ""),
                            server=server,
                            to_version=cmd_data.get("latest_version", ""),
                        )
                except: pass
            
            await asyncio.sleep(30)
        except Exception as e:
            logger.warning("Poll error: %s", str(e)[:60])
            await asyncio.sleep(60)

# ═══════════════════════════════════════════════════════
#  Self-update
# ═══════════════════════════════════════════════════════

MAX_UPDATE_ATTEMPTS = 5          # total attempts per process
MAX_ATTEMPTS_PER_VERSION = 2     # one retry per release, then leave it to the next reconnect
MIN_UPDATE_INTERVAL = 30         # seconds between attempts (no tight retry loops)
_update_attempts = 0
_update_last_at = 0.0
_update_versions: dict = {}      # target version -> attempts
_current_ws = None               # set while the WS connection is live
_deferred_frames: list = []      # frames read during the registration handshake


def _ver_tuple(v) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", str(v or ""))[:3]) or (0,)


def _agent_script_path() -> str:
    """The script this process is actually running — not necessarily __file__."""
    candidate = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if candidate.endswith(".py") and os.path.isfile(candidate):
        return candidate
    return os.path.abspath(__file__)


def _update_state_file() -> str:
    for base in (os.path.expanduser("~"), os.path.dirname(_agent_script_path())):
        if base and os.path.isdir(base):
            return os.path.join(base, ".soc-agent-update.json")
    return ".soc-agent-update.json"


def _save_update_state(**fields) -> None:
    path = _update_state_file()
    try:
        state = {}
        if os.path.exists(path):
            with open(path) as f:
                state = json.load(f)
        state.update(fields)
        with open(path, "w") as f:
            json.dump(state, f, indent=2, default=str)
    except Exception:
        pass


async def _fetch(url: str) -> bytes:
    """GET the published agent — aiohttp when available, urllib otherwise."""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=45)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                return await resp.read()
    except ImportError:
        import urllib.request as _ur
        return await asyncio.to_thread(lambda: _ur.urlopen(url, timeout=45).read())


async def _notify_update(result: dict) -> None:
    ws = _current_ws
    if ws is not None:
        try:
            await ws.send_json({"type": "update", "data": result})
            await asyncio.sleep(0.3)
        except Exception:
            pass


def _windows_update_shim(exe: str, new_path: str, old_path: str, log_path: str, args: str) -> str:
    """Batch shim that swaps the running exe for the staged one.

    Retries the rename (the onefile bootloader holds the image briefly), keeps
    the old build until the swap succeeds, relaunches with the original args and
    falls back to restarting the old build. Logs every step.
    """
    exe_dir = os.path.dirname(exe)
    return (
        "@echo off\r\n"
        "setlocal enabledelayedexpansion\r\n"
        f'set "EXE={exe}"\r\n'
        f'set "NEW={new_path}"\r\n'
        f'set "OLD={old_path}"\r\n'
        f'set "LOG={log_path}"\r\n'
        'echo [%DATE% %TIME%] updater start > "%LOG%"\r\n'
        "set /a tries=0\r\n"
        ":wait\r\n"
        "ping -n 3 127.0.0.1 >nul\r\n"
        f'move /y "%EXE%" "%OLD%" >> "%LOG%" 2>&1\r\n'
        f'if exist "%EXE%" (\r\n'
        "  set /a tries+=1\r\n"
        "  if !tries! lss 30 goto wait\r\n"
        ")\r\n"
        f'if exist "%EXE%" (\r\n'
        '  echo swap failed after !tries! tries - restarting old build >> "%LOG%"\r\n'
        + (f'  start "" /d "{exe_dir}" "%EXE%" {args}\r\n' if args else f'  start "" /d "{exe_dir}" "%EXE%"\r\n')
        + '  del "%~f0" >nul 2>nul\r\n'
        "  exit /b 0\r\n"
        ")\r\n"
        f'move /y "%NEW%" "%EXE%" >> "%LOG%" 2>&1\r\n'
        f'del "%OLD%" >nul 2>nul\r\n'
        'taskkill /f /im SOCAgent.exe >nul 2>nul\r\n'
        + (f'start "" /d "{exe_dir}" "%EXE%" {args}\r\n' if args else f'start "" /d "{exe_dir}" "%EXE%"\r\n')
        + 'echo [%DATE% %TIME%] swapped + relaunched >> "%LOG%"\r\n'
        'del "%~f0" >nul 2>nul\r\n'
    )


def _stage_frozen_update(new_exe: bytes) -> str:
    """Swap a running PyInstaller exe for the downloaded one. Returns '' on success.

    Windows keeps the running image locked (the onefile bootloader holds it even
    after the python child exits), so a detached cmd shim retries the rename, then
    relaunches with the original arguments. If the swap cannot be completed the
    shim relaunches the *old* build, so an agent is never left dead.
    """
    exe = os.path.abspath(sys.executable)
    exe_dir = os.path.dirname(exe)
    new_path = os.path.join(exe_dir, "SOCAgent.new.exe")
    old_path = exe + ".old"
    cmd_path = os.path.join(exe_dir, "soc-agent-update.cmd")
    log_path = os.path.join(exe_dir, "soc-agent-update.log")
    try:
        with open(new_path, "wb") as f:
            f.write(new_exe)
    except Exception as e:
        return f"cannot stage update: {str(e)[:120]}"

    if os.name != "nt":
        # POSIX lets a running image be replaced in place; no shim needed.
        try:
            os.chmod(new_path, 0o755)
            shutil.copy2(exe, old_path)
            os.replace(new_path, exe)
        except Exception as e:
            return f"replace failed: {str(e)[:120]}"
        return ""

    args = " ".join(f'"{a}"' if " " in a else a for a in sys.argv[1:])
    # NOTE: 'ping -n' is the sleep that works without a console; taskkill/timeout do not.
    script = _windows_update_shim(exe, new_path, old_path, log_path, args)

    try:
        with open(cmd_path, "w", newline="") as f:
            f.write(script)
        flags = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(["cmd", "/c", cmd_path], creationflags=flags, close_fds=True)
    except Exception as e:
        return f"cannot start updater: {str(e)[:120]}"
    return ""


async def perform_self_update(download_url: str = "", expected_sha: str = "",
                              server: str = "", notify=None,
                              to_version: str = "") -> dict:
    """Download the published agent, verify it, replace this build.

    Script builds are replaced atomically in place; packaged (.exe) builds are
    staged and swapped by a detached updater after this process exits. Either
    way the update only happens for a verified, newer payload — a failed
    download, checksum mismatch or syntax error leaves the running agent alone,
    and each process attempts at most MAX_UPDATE_ATTEMPTS updates.
    """
    global _update_attempts
    me = AGENT_VERSION
    frozen = bool(getattr(sys, "frozen", False))
    result = {"success": False, "from": me, "to": to_version or me, "error": ""}

    def done(err: str = "") -> dict:
        result["error"] = err
        _save_update_state(last_result=result, at=time.time())
        return result

    global _update_last_at
    if _update_attempts >= MAX_UPDATE_ATTEMPTS:
        return done("update attempts exhausted in this process")
    if to_version and _update_versions.get(to_version, 0) >= MAX_ATTEMPTS_PER_VERSION:
        return done(f"already attempted {to_version} twice in this process")
    if time.time() - _update_last_at < MIN_UPDATE_INTERVAL:
        return done("update attempted too recently")
    _update_attempts += 1
    _update_last_at = time.time()
    if to_version:
        _update_versions[to_version] = _update_versions.get(to_version, 0) + 1

    default_path = "/api/agent/download/exe" if frozen else f"/api/agent/download/agent?platform={get_platform()}"
    url = download_url or (f"http://{server}{default_path}" if server else "")
    if not url:
        return done("no download url")

    try:
        new_code = await _fetch(url)
    except Exception as e:
        return done(f"download failed: {str(e)[:120]}")

    min_bytes = 1000 if not frozen else 100_000      # a real onefile exe is megabytes
    if not new_code or len(new_code) < min_bytes:
        return done(f"suspicious payload ({len(new_code)} bytes)")
    # Shape check before anything is written: a captive portal / SSO login page
    # answers 200 with HTML, and installing that would brick the agent.
    if frozen and not new_code.startswith(b"MZ"):
        return done("payload is not a Windows executable (login page?)")
    if not frozen and b"AGENT_VERSION" not in new_code[:8192]:
        return done("payload does not look like the agent script")
    if expected_sha and hashlib.sha256(new_code).hexdigest() != expected_sha:
        return done("sha256 mismatch")

    if frozen:
        # The payload is a binary: the target version comes from the server.
        result["to"] = to_version or me
        if not to_version or _ver_tuple(to_version) <= _ver_tuple(me):
            return done(f"payload version {to_version or '?'} is not newer than {me}")
        if not expected_sha:
            return done("packaged build requires a sha256 from the server")
        err = _stage_frozen_update(new_code)
        if err:
            return done(err)
        result["success"] = True
        result["staged"] = True      # swap happens after this process exits
        _save_update_state(last_result=result, at=time.time(), installed=os.path.abspath(sys.executable))
        logger.info("Self-update staged %s -> %s (%d bytes); swapping after exit",
                    me, result["to"], len(new_code))
        notify = notify or _notify_update
        try:
            await notify(result)
        except Exception:
            pass
        raise SystemExit(0)          # the updater shim waits for this exit

    m = re.search(rb'^AGENT_VERSION\s*=\s*"([^"]+)"', new_code, re.M)
    new_ver = m.group(1).decode() if m else ""
    result["to"] = new_ver or me
    if not new_ver or _ver_tuple(new_ver) <= _ver_tuple(me):
        return done(f"payload version {new_ver or '?'} is not newer than {me}")

    script_path = _agent_script_path()
    tmp_path = script_path + ".new"
    try:
        with open(tmp_path, "wb") as f:
            f.write(new_code)
        os.chmod(tmp_path, 0o755)
        py_compile.compile(tmp_path, cfile=tmp_path + "c", doraise=True)
        os.remove(tmp_path + "c")
    except Exception as e:
        for p in (tmp_path, tmp_path + "c"):
            try:
                os.remove(p)
            except OSError:
                pass
        return done(f"payload rejected: {str(e)[:120]}")

    try:
        shutil.copy2(script_path, script_path + ".bak")
        os.replace(tmp_path, script_path)      # atomic on POSIX; atomic-ish on Windows
    except Exception as e:
        return done(f"replace failed: {str(e)[:120]}")

    result["success"] = True
    _save_update_state(last_result=result, at=time.time(), installed=script_path)
    logger.info("Self-update installed %s -> %s (%d bytes)", me, new_ver, len(new_code))

    notify = notify or _notify_update
    try:
        await notify(result)
    except Exception:
        pass

    # Restart in place. The launcher stays responsible for the process:
    # systemd Restart=always on Linux, the scheduled task / cmd wrapper on Windows.
    try:
        os.execl(sys.executable, sys.executable, script_path, *sys.argv[1:])
    except Exception as e:
        result["error"] = f"restart failed (new version is on disk): {str(e)[:120]}"
        try:
            await notify(result)
        except Exception:
            pass
    return result


async def _await_registered(ws, timeout: float = 10.0) -> dict:
    """Wait for the registration ack; queue any earlier command frames."""
    import aiohttp as _aiohttp
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return {}
        try:
            msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
        except asyncio.TimeoutError:
            return {}
        if msg.type != _aiohttp.WSMsgType.TEXT:
            continue
        try:
            data = json.loads(msg.data)
        except Exception:
            continue
        if data.get("type") == "registered":
            return data
        _deferred_frames.append(data)


async def _handle_frame(ws, data: dict) -> None:
    """Dispatch one server frame (command or telemetry request)."""
    cmd = data.get("command", "")
    args = data.get("args", {})
    cmd_id = data.get("id", "")

    handler_fn = HANDLERS.get(cmd)
    if handler_fn:
        result = await handler_fn(args)
        await ws.send_json({"type": "result", "id": cmd_id, "command": cmd, "result": result})
    elif cmd == "telemetry_request":
        telemetry = {
            "system": collect_system_info(),
            "processes": collect_processes(50),
            "network": collect_network(),
            "disks": collect_disks(),
        }
        await ws.send_json({"type": "telemetry", "id": cmd_id, "data": telemetry})


# ═══════════════════════════════════════════════════════
#  WebSocket Client
# ═══════════════════════════════════════════════════════

async def run(server: str, api_key: str = ""):
    """Connect to SOC server and handle commands.
    Uses aiohttp WebSocket if available, falls back to HTTP polling."""
    # isolate() must know the collector before any command can arrive.
    _set_collector(server)
    try:
        import aiohttp
        _has_aiohttp = True
    except ImportError:
        _has_aiohttp = False
        import urllib.request as _ur
        import json as _json
        logger.info("aiohttp not available, using HTTP polling mode")

    global _agent_id, _current_ws
    _agent_id = str(uuid.uuid4())[:8]
    url = f"http://{server}/api/agent/ws"
    wait = RECONNECT_BASE
    session = None

    while True:
        try:
            if session is None:
                session = aiohttp.ClientSession()

            headers = {"X-EDR-Key": api_key} if api_key else {}
            async with session.ws_connect(url, headers=headers, heartbeat=HEARTBEAT_INTERVAL) as ws:
                logger.info("Connected to %s", server)
                wait = RECONNECT_BASE
                _current_ws = ws

                # Register
                info = collect_system_info()
                info["agent_id"] = _agent_id
                await ws.send_json({"type": "register", "data": info})

                # Registration ack: tells us whether we are current, and hands us a
                # download URL built from the address we just reached the server on.
                ack = await _await_registered(ws)
                if ack.get("needs_update"):
                    logger.info("Auto-update offered: %s -> %s", AGENT_VERSION,
                                ack.get("latest_version", "?"))
                    await perform_self_update(
                        download_url=ack.get("download_url", ""),
                        expected_sha=ack.get("agent_sha256", ""),
                        server=server,
                        to_version=ack.get("latest_version", ""),
                    )
                    # Still running => the update did not restart us (it logged why).

                # Start telemetry loop
                last_telemetry = 0
                
                # Start background event log forwarder (Windows only)
                evtlog_task = None
                if get_platform() == "windows":
                    async def forward_events():
                        last_ts = ""
                        while True:
                            try:
                                import subprocess as _sp
                                log_name = "Security"
                                max_events = 30
                                r = _sp.run(
                                    ["wevtutil", "qe", log_name, "/c:" + str(max_events), "/rd:true", "/f:text"],
                                    capture_output=True, text=True, timeout=30,
                                )
                                if r.returncode == 0:
                                    raw_events = []
                                    current = {}
                                    for line in r.stdout.strip().split("\n"):
                                        line = line.strip()
                                        if not line:
                                            if current:
                                                raw_events.append(current)
                                                current = {}
                                            continue
                                        if ":" in line:
                                            key, val = line.split(":", 1)
                                            current[key.strip()] = val.strip()
                                    if current:
                                        raw_events.append(current)
                                    
                                    if raw_events and raw_events[0].get("Date", "") != last_ts:
                                        last_ts = raw_events[0].get("Date", "")
                                        siem_events = []
                                        for ev in raw_events:
                                            eid = ev.get("EventID", "?"),
                                            msg = ev.get("Message", ev.get("Description", ""))[:200]
                                            sev = "medium"
                                            if ev.get("Level", "") in ("2", "Error", "Critical"):
                                                sev = "high"
                                            siem_events.append({
                                                "source": "windows_eventlog",
                                                "source_name": get_hostname(),
                                                "event_type": f"Event_{eid[0]}",
                                                "severity": sev,
                                                "message": msg,
                                                "timestamp": ev.get("Date", ""),
                                                "user": ev.get("User", ""),
                                            })
                                        if siem_events:
                                            import aiohttp as _aiohttp
                                            async with _aiohttp.ClientSession() as s:
                                                await s.post(f"http://{server}/api/siem/ingest",
                                                    json=siem_events)
                            except: pass
                            await asyncio.sleep(60)
                    
                    evtlog_task = asyncio.create_task(forward_events())

                # Frames that arrived during the handshake, then the live stream.
                while _deferred_frames:
                    await _handle_frame(ws, _deferred_frames.pop(0))

                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await _handle_frame(ws, json.loads(msg.data))
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        logger.error("WebSocket error: %s", msg.data)
                        break

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning("Connection failed: %s (reconnect in %ds)", str(e)[:60], wait)

        _current_ws = None
        if session:
            await session.close()
            session = None

        await asyncio.sleep(wait)
        wait = min(wait * 2, 300)


def main():
    parser = argparse.ArgumentParser(description="Unified SOC Agent")
    parser.add_argument("--server", default="173.208.232.91:8095", help="SOC server")
    parser.add_argument("--key", default="", help="API key")
    args = parser.parse_args()

    try:
        asyncio.run(run(args.server, args.key))
    except KeyboardInterrupt:
        logger.info("Shutdown")


# Everything above registers at import time; the __main__ guard lives at the very
# end of the file so the handlers defined below it are in HANDLERS before the
# agent starts listening. (With the guard here, server-pushed commands such as
# self_update / eventlog / fim_scan were silently ignored.)


@handler("eventlog")
async def cmd_eventlog(args: dict) -> dict:
    """Collect Windows Event Log entries (Security, Application, System).
    Works on Windows via wevtutil. Returns recent events.
    """
    if get_platform() != "windows":
        return {"success": False, "error": "Event log collection requires Windows"}
    
    log_name = args.get("log", "Security")
    max_events = min(args.get("max", 50), 200)
    
    try:
        # Use wevtutil to query events (fast, built into Windows)
        r = subprocess.run(
            ["wevtutil", "qe", log_name, "/c:" + str(max_events), "/rd:true", "/f:text"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return {"success": False, "error": r.stderr.strip()}
        
        events = []
        current = {}
        for line in r.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                if current:
                    events.append(current)
                    current = {}
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                current[key.strip()] = val.strip()
        
        if current:
            events.append(current)
        
        # Also forward to SIEM
        siem_url = args.get("siem_url", "")
        if siem_url and events:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    await session.post(siem_url, json={
                        "source": "windows_eventlog",
                        "source_name": get_hostname(),
                        "events": events[:20],
                    })
            except: pass
        
        return {"success": True, "count": len(events), "events": events[:max_events]}
    
    except FileNotFoundError:
        return {"success": False, "error": "wevtutil not found (not Windows)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@handler("forward_logs")
async def cmd_forward_logs(args: dict) -> dict:
    """Forward recent Windows Event Logs to SIEM endpoint."""
    siem_url = args.get("siem_url", "")
    if not siem_url:
        return {"success": False, "error": "siem_url required"}
    
    result = await cmd_eventlog({"log": "Security", "max": 20, "siem_url": siem_url})
    return result





@handler("self_update")
async def cmd_self_update(args: dict) -> dict:
    """Server-initiated update: same verified path as the on-connect check."""
    result = await perform_self_update(
        download_url=args.get("url", ""),
        expected_sha=args.get("sha256", ""),
        server=args.get("server", ""),
        to_version=args.get("version", ""),
    )
    return {"success": result["success"], "from": result["from"], "to": result["to"],
            "error": result["error"]}

@handler("fim_scan")
async def cmd_fim_scan(args: dict) -> dict:
    """File Integrity Monitoring — scan watched files and report changes.
    
    Args:
        paths: list of file paths to check, or ["all"] for defaults
        prev_scan: optional dict of {path: hash} from previous scan
    
    Returns:
        {files: [{path, hash, size, mtime, exists, changed}], changes: [...]}
    """
    import os as _os
    import hashlib as _hashlib
    from datetime import datetime as _dt
    import stat as _stat
    
    paths = args.get("paths", [])
    prev_scan = args.get("prev_scan", {})
    
    if not paths:
        # Use platform defaults
        plat = get_platform()
        if plat == "linux":
            paths = [
                "/etc/passwd", "/etc/shadow", "/etc/hosts",
                "/etc/ssh/sshd_config", "/etc/crontab",
                _os.path.expanduser("~/.ssh/authorized_keys"),
            ]
        elif plat == "windows":
            paths = [r"C:\Windows\System32\drivers\etc\hosts"]
        else:
            paths = ["/etc/passwd", "/etc/hosts"]
    
    results = []
    changes = []
    
    for filepath in paths:
        try:
            if not _os.path.exists(filepath):
                results.append({"path": filepath, "exists": False, "hash": "", "size": 0})
                if filepath in prev_scan:
                    changes.append({
                        "filepath": filepath,
                        "change_type": "deleted",
                        "old_hash": prev_scan[filepath],
                        "new_hash": "",
                    })
                continue
            
            st = _os.stat(filepath)
            filesize = st.st_size
            mtime = _dt.fromtimestamp(st.st_mtime).isoformat()
            
            # Compute SHA256
            sha = _hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    block = f.read(65536)
                    if not block:
                        break
                    sha.update(block)
            filehash = sha.hexdigest()
            
            fileinfo = {
                "path": filepath,
                "exists": True,
                "hash": filehash,
                "size": filesize,
                "mtime": mtime,
                "mode": oct(_stat.S_IMODE(st.st_mode)),
            }
            results.append(fileinfo)
            
            # Check for changes
            prev = prev_scan.get(filepath)
            if prev and prev != filehash:
                changes.append({
                    "filepath": filepath,
                    "change_type": "modified",
                    "old_hash": prev,
                    "new_hash": filehash,
                    "old_size": 0,
                    "new_size": filesize,
                })
            elif filepath not in prev_scan:
                changes.append({
                    "filepath": filepath,
                    "change_type": "created",
                    "old_hash": "",
                    "new_hash": filehash,
                })
                
        except PermissionError:
            results.append({"path": filepath, "exists": True, "hash": "", "error": "permission denied"})
        except Exception as e:
            results.append({"path": filepath, "exists": False, "hash": "", "error": str(e)})
    
    # Store snapshot for next comparison
    snapshot = {r["path"]: r["hash"] for r in results if r.get("hash")}
    
    return {
        "success": True,
        "files": results,
        "changes": changes,
        "snapshot": snapshot,
        "change_count": len(changes),
    }



@handler("packages")
async def cmd_packages(args: dict) -> dict:
    """Collect installed packages from the system.
    
    Supports: dpkg (Debian), rpm (RHEL), pip (Python), pkg (macOS), wmic (Windows)
    Returns: list of {name, version, source, arch, vendor}
    """
    import subprocess as _sp
    plat = get_platform()
    packages = []
    
    try:
        if plat == "linux":
            # Try dpkg first
            r = _sp.run(["dpkg", "-l"], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n")[5:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] in ("ii", "hi", "rc"):
                        packages.append({
                            "name": parts[1],
                            "version": parts[2],
                            "arch": parts[3] if len(parts) > 3 else "",
                            "source": "dpkg",
                        })
            else:
                # Try rpm
                r = _sp.run(["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{ARCH}\n"], 
                           capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    for line in r.stdout.strip().split("\n"):
                        parts = line.split("|")
                        if len(parts) >= 2:
                            packages.append({"name": parts[0], "version": parts[1], "arch": parts[2] if len(parts) > 2 else "", "source": "rpm"})
            
            # pip packages
            r = _sp.run(["pip3", "list", "--format=freeze"], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    if "==" in line:
                        name, ver = line.split("==", 1)
                        packages.append({"name": name.strip(), "version": ver.strip(), "source": "pip"})
        
        elif plat == "windows":
            r = _sp.run(["wmic", "product", "get", "name,version,vendor", "/format:csv"], 
                       capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n")[2:]:
                    parts = line.split(",")
                    if len(parts) >= 4:
                        packages.append({"name": parts[1].strip(), "version": parts[2].strip(), "vendor": parts[3].strip(), "source": "wmic"})
        
        elif plat == "macos":
            r = _sp.run(["pkgutil", "--pkgs"], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    packages.append({"name": line.strip(), "source": "pkgutil"})
    
    except Exception as e:
        return {"success": False, "error": str(e), "packages": []}
    
    return {"success": True, "count": len(packages), "packages": packages[:500]}

@handler("vuln_packages")
async def cmd_vuln_packages(args: dict) -> dict:
    """Collect packages and check against cached CVE database via SOC server."""
    result = await cmd_packages(args)
    if not result.get("success"):
        return result
    return result




if __name__ == "__main__":
    main()
