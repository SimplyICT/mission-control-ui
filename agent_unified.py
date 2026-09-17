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
import hashlib
import json
import logging
import os
import platform
import py_compile
import re
import shutil
import subprocess
import sys
import time
import uuid

logging.basicConfig(level=logging.INFO, format="%(asctime)s agent %(message)s")
logger = logging.getLogger("agent")

AGENT_VERSION = "1.1.7"
RECONNECT_BASE = 5
HEARTBEAT_INTERVAL = 30
TELEMETRY_INTERVAL = 60

_agent_id = None


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


@handler("isolate")
async def cmd_isolate(args: dict) -> dict:
    plat = get_platform()
    try:
        if plat == "windows":
            # Windows: block all non-essential traffic via Windows Firewall
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=EDR_ISOLATE", "dir=in", "action=block", "enable=yes"],
                capture_output=True, text=True, timeout=15,
            )
            return {"success": r.returncode == 0, "detail": r.stderr.strip() or "isolated"}
        else:
            from edr_actions import isolate_agent
            return isolate_agent("local")
    except Exception as e:
        return {"success": False, "error": str(e)}


@handler("release")
async def cmd_release(args: dict) -> dict:
    plat = get_platform()
    try:
        if plat == "windows":
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR_ISOLATE"],
                capture_output=True, text=True, timeout=15,
            )
            return {"success": r.returncode == 0, "detail": "released"}
        else:
            from edr_actions import release_agent
            return release_agent("local")
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════
#  HTTP Polling Fallback (when aiohttp not available)
# ═══════════════════════════════════════════════════════

async def _polling_mode(server: str):
    """HTTP polling mode — polls the server for commands every 30s.
    Used when aiohttp is not available (e.g., macOS without pip).
    """
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
