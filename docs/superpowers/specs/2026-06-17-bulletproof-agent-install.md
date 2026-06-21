# Bulletproof Probe Agent Install

## Problem

The probe agent depends on system Python, which leads to failures when:
- Python is installed via Microsoft Store (stub executables break when the real install is removed)
- The venv `python.exe` becomes a dead symlink to a deleted AppData path
- Different Windows machines have different Python configurations
- Python gets updated/uninstalled and breaks the agent silently

## Solution: Embeddable Python + No System Dependencies

The agent ships with its own Python runtime — the embeddable distribution from python.org. This is a ~12MB zip file containing Python, the standard library, and just enough to run the agent.

### Key Properties

- **No installer required** — it's a zip, not an MSI
- **No registry changes** — no HKLM, no AppData, no stubs
- **No system-wide Python** — the agent's Python lives in its own directory
- **No venv** — the embeddable Python is used directly (pip installs into its site-packages)
- **Self-contained** — everything under `%ProgramFiles%\Mission Probe\current\`
- **Survives any system Python changes** — system Python can be installed, moved, or deleted without affecting the agent

### Directory Structure

```
C:\Program Files\Mission Probe\
├── current\                         # agent version
│   ├── mission_probe\               # probe source code (from tarball)
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── client.py
│   │   ├── scanner.py
│   │   ├── enrichment.py
│   │   ├── updater.py
│   │   └── deploy\
│   │       ├── install.ps1
│   │       ├── install.sh
│   │       ├── probe-diagnose.ps1
│   │       ├── config.toml.example
│   │       └── mission-probe.service  # Linux systemd unit
│   ├── python\                      # embeddable Python
│   │   ├── python.exe
│   │   ├── python314.dll
│   │   ├── python3.dll
│   │   ├── python314._pth.bak       # renamed to enable pip
│   │   ├── Lib\
│   │   │   └── site-packages\
│   │   │       ├── mission_probe.pth  # points to ..\..\..\ (current\)
│   │   │       ├── requests\
│   │   │       └── ...
│   │   └── ... (DLLs, stdlib)
│   └── pyproject.toml
├── logs\
│   ├── stdout.log
│   └── stderr.log
├── backup\                          # previous version (for rollback)
└── run-agent.bat                    # convenience runner
```

## Install Flow

1. **Admin check** — requires elevated PowerShell
2. **NSSM** — downloaded and installed to `C:\Windows\System32\nssm.exe` (if missing)
3. **Embeddable Python** — downloaded from `python.org` and extracted to `$CurrentDir\python\`
4. **Agent package** — downloaded from backend API and extracted to `$CurrentDir\`
5. **`.pth` file** — created at `python\Lib\site-packages\mission_probe.pth` pointing to `$CurrentDir`
6. **`._pth` renamed** — `python314._pth` → `python314._pth.bak` (enables full import resolution)
7. **Pip & requests** — installed into embeddable Python
8. **Verification** — imports `mission_probe` and `requests`, confirms versions
9. **Service** — NSSM service installed, starts automatically at boot
10. **Env file** — written to `%ProgramData%\mission-probe\env.ps1`

## Diagnostic Script

`probe-diagnose.ps1` checks:
- Installation paths exist
- Python executable works
- `mission_probe` and `requests` import correctly
- Config file exists with valid settings
- Service status (running/stopped/absent)
- Log file presence and content
- API endpoint reachability

Run as: `powershell -ExecutionPolicy Bypass .\probe-diagnose.ps1`

## Self-Update Safety

When the agent self-updates (checks for new versions every N cycles):
1. Downloads new tarball to a temp directory
2. Extracts alongside existing `current/`
3. Creates a new `python/` directory (only if the version changed)

The existing Python environment is reused across updates (Python version only changes when the bundled embeddable changes).

## Windows Service Details

- **Service name:** `MissionProbe`
- **Process:** `python.exe -m mission_probe`
- **Account:** `LocalSystem`
- **Start type:** `Automatic`
- **Environment:** Set via NSSM `AppEnvironmentExtra` (API key, site ID, etc.)
- **Logs:** Rotated daily, kept in `%ProgramFiles%\Mission Probe\logs\`

## Manual Commands

```powershell
# Install
.\install.ps1 -ApiKey "key" -SiteId "SITE-ID" -SiteName "Name" -AgentId "AGENT-ID" -Subnet "192.168.1.0/24"

# Diagnose
.\probe-diagnose.ps1

# Check service
nssm status MissionProbe

# View logs
type "$env:ProgramFiles\Mission Probe\logs\stdout.log"
type "$env:ProgramFiles\Mission Probe\logs\stderr.log"

# Run manually (no service)
& "$env:ProgramFiles\Mission Probe\current\python\python.exe" -m mission_probe --verbose

# Restart service
nssm restart MissionProbe
```
