# Mission Control — ACECQA Compliance & Network Monitoring Platform

> Device audit, remediation, incident management, governance dashboard, and site probe agent platform for early childhood education services.
> Live at **[audit.simplyict.com.au](https://audit.simplyict.com.au)**

---

## Architecture

```
Audit stack:
nginx (443/80)  ──►  mission-control-ui  (Flask, port 8095)  ──►  HTML/JS frontend
                ──►  device-audit-api    (FastAPI, port 8096) ──►  Supabase (PostgreSQL)

Monitoring stack:
site_probe (NUC) ──►  backend-api (FastAPI, port 8000) ──►  Supabase (PostgreSQL)
```

### Audit & Compliance

| Component | Path | Service |
|---|---|---|
| Auth + session proxy | `ui/app.py` | `mission-control-ui.service` |
| Audit API | `ui/device_audit_api.py` | `device-audit-api.service` |
| PDF generator | `ui/pdf_report_generator.py` | — |
| Supabase backup | `supabase_backup.py` | `supabase-backup.timer` |
| Nightly git push | `autopush.sh` | `mc-autopush.timer` |

### Network Monitoring (Probe Agent Platform)

| Component | Path | Service |
|---|---|---|
| Backend API | `site/backend_api.py` | `backend-api.service` |
| Probe agent package | `site/mission_probe/` | `mission-probe.service` |
| Agent deploy scripts | `site/mission_probe/deploy/` | — |

---

## Probe Agent Platform

The probe agent runs on an Intel NUC at each client site. It performs periodic ARP + ICMP discovery of the local subnet and reports device state to the central backend.

### Agent Package (`site/mission_probe/`)

```
mission_probe/
├── __init__.py          # Package version
├── __main__.py          # python -m mission_probe entry
├── main.py              # Main loop, signal handling
├── config.py            # Config loader (CLI > env > TOML > defaults)
├── scanner.py           # Subnet scan (ICMP ping + ARP)
├── enrichment.py        # MAC vendor, device type, DNS reverse lookup
├── client.py            # API client (heartbeat, report, update check)
├── updater.py           # Self-update orchestration
├── pyproject.toml       # Package build config
└── deploy/
    ├── mission-probe.service     # systemd unit
    ├── install.sh               # Linux install script
    └── config.toml.example      # Example config
```

**Per-cycle flow:**

```
Agent: scan_subnet() → 200+ devices
  → POST /api/v1/heartbeat              (1 HTTP call)
  → POST /api/v1/devices/report          (1 HTTP call)
    → Backend:
        → batch upsert_devices()         (1 RPC call)
        → bulk_insert_observations()     (1 RPC call)
        → sweep_offline_devices()        (1 RPC call)
Total: 4 HTTP calls per cycle per site
```

**Self-update:** Agent polls `GET /api/v1/agent/release?current=v8` every N cycles. If a new version is available, it downloads, validates, sym-swaps `/opt/mission-probe/current`, and restarts via systemd.

### Backend Monitoring API (`site/backend_api.py`)

FastAPI application providing:
- `POST /api/v1/heartbeat` — Agent heartbeat + system metrics
- `POST /api/v1/devices/report` — Batch device report (batch RPC, ~400 calls → 3)
- `GET /api/v1/agent/release` — Latest agent version for self-update
- `GET/POST /api/v1/agent/releases` — Release management (admin)
- `POST /api/v1/agent/health-check` — Detect stale agents → `AGENT_MISSING` alerts
- `GET /api/v1/dashboard/summary` — Per-site dashboard
- `GET /api/v1/dashboard/all-sites` — Multi-site overview
- `GET /api/v1/executive/availability` — Executive intelligence
- `POST /api/v1/alerts/*` — Alert CRUD, acknowledge, resolve, suppress
- `GET /api/v1/events/stream` — SSE real-time updates

---

## Features

### Authentication & Security
- Session login with **brute-force protection** — 5 attempts → 15-min lockout
- Cloudflare `X-Forwarded-For`-aware IP tracking
- **TOTP 2FA** (pyotp) — QR code setup, per-user activate/disable, admin reset (`ui/2fa-setup.html`, `ui/2fa-verify.html`)

### Device Audit
- Per-site audit batches stored in `device_audits` + `audit_entries` tables
- `classify()` applies **per-site** photo retention days and count thresholds
- Risk scoring: Critical → High Risk, Warnings → Needs Attention, Clean → On Track
- PDF executive report with policy compliance checklist section
- CSV import (upsert on `device_id`) and 26-column CSV export

### Site Onboarding (`ui/site-onboarding.html`)
9 ACECQA policy toggles per site:
- Consent forms current
- Photo policy documented
- Staff privacy training current
- Device encryption enforced
- Access controls documented
- Data retention policy in place
- Incident response plan exists
- Privacy impact assessment completed
- Third-party data agreements in place

### Governance Dashboard (`ui/director-view.html`)
Powered by `GET /governance-summary`:
- **11 KPI tiles** — remediations (open/overdue/resolved/critical/high), incidents (open/mandatory/critical/high), policy gaps, sites complete
- **Per-site policy table** — confirmed/9, gaps, not-set, missing policy names
- **Audit recency table** — last audit date + age, overdue flag >90 days
- **NQS mapping** — findings mapped to NQS 2.2, 7.1, 7.2

### Director Dashboard (`GET /director-dashboard`)
- Latest audit per site + last-30-day audit history
- Bulk-query design: **3 Supabase queries total** regardless of audit count (was N×3, was 55s, now 2.4s)

### Incident Register (`ui/incident-register.html`)
- Full CRUD + DELETE; mandatory-reportable flagging; severity levels

### Remediation Register (`ui/remediation.html`)
- Priority/severity tracking; overdue detection; open/resolved/accepted-risk states

### Wazuh SOC Dashboard (ui/wazuh-soc.html)
Full Wazuh SIEM single-page application with 14 views, proxied through app.py:
- **Command Center** — KPI tiles (agents, vulnerabilities, SCA score, threat index) + Chart.js charts
- **Agents** — Filterable agent list with drill-down to SCA, FIM, vulnerabilities, inventory tabs
- **SCA Compliance** — Fleet-wide Security Configuration Assessment scores and policy results
- **File Integrity** — FIM event log across all agents
- **Vulnerabilities** — CVE aggregation with severity KPIs and sortable table
- **MITRE ATT&CK** — Technique heatmap grid
- **Rules & Decoders** — Wazuh rule/decoder catalogue browser
- **Events & Alerts** — Real-time alert feed with severity filtering (Critical/High/Medium/Low)
- **Topology** — OS distribution and agent version charts
- **Threat Intel** — AlienVault OTX integration status and IOC counts
- **SOC Autopilot** — AI-powered case management with approve/reject/execute workflow
- **Manager Health** — Daemon status, manager info, cluster status
- **Groups** — Agent group membership

#### Wazuh API Proxy
app.py includes a server-side proxy (/wazuh-api/{path}) that forwards requests to the Wazuh SOC API at 127.0.0.1:8000. Authentication is handled automatically — the proxy logs in, caches the bearer token, and retries on 401.

---

## Database Tables (Supabase)

### Audit & Compliance

| Table | Purpose |
|---|---|
| `sites` | Site config, policy toggles, thresholds |
| `devices` | Device inventory |
| `device_audits` | Audit batch metadata |
| `audit_entries` | Per-device audit results |
| `remediation_actions` | Remediation items |
| `incidents` | Incident register |

### Network Monitoring

| Table | Purpose |
|---|---|
| `mc_sites` | Monitoring site definitions |
| `mc_probe_agents` | Probe agent registration + heartbeat tracking |
| `mc_probe_heartbeats` | Agent heartbeat log with system metrics |
| `mc_network_devices` | Discovered network devices (upsert by site+MAC) |
| `mc_device_observations` | Per-scan-cycle observation log |
| `mc_device_patterns` | Historical offline/online patterns (severity adjustment) |
| `mc_alerts` | Alert management (DEVICE_OFFLINE, AGENT_MISSING, etc.) |
| `mc_agent_releases` | Agent version releases for self-update |
| `mc_network_metrics` | Network performance metrics |
| `mc_incidents` | Monitoring incidents |
| `mc_audit_device_links` | Links between monitoring and audit devices |

---

## Deployment

### Server
- **Host**: `208.87.135.84`
- **Domain**: `audit.simplyict.com.au`
- **SSL**: Let's Encrypt via Certbot (Cloudflare Full Strict)
- **OS**: Ubuntu, user `aiagent`
- **App dir**: `/home/aiagent/mission-control-ui/`

### Environment
```
/home/aiagent/mission-control-site/.env
```
Required vars: `SUPABASE_URL`, `SUPABASE_KEY`, `SECRET_KEY`, `ADMIN_PASSWORD`

### Service Management
```bash
# Audit stack
sudo systemctl restart device-audit-api mission-control-ui

# Monitoring stack
sudo systemctl start backend-api
sudo systemctl start mission-probe

# Status check
sudo systemctl status device-audit-api mission-control-ui backend-api nginx
```

### Deploying a Probe Agent

#### Linux

```bash
# Use the install script directly from the repo:
sudo ./site/mission_probe/deploy/install.sh \
  --api-key sk-... \
  --api-base https://audit.simplyict.com.au/monitoring-api \
  --site-id site-benowa-elc \
  --site-name "Benowa ELC" \
  --agent-id probe-benowa-nuc-01 \
  --subnet 192.168.1.0/24
```

#### Windows (Intel NUC)

Run as **Administrator** in PowerShell:

```powershell
.\site\mission_probe\deploy\install.ps1 `
  -ApiKey sk-... `
  -ApiBase https://audit.simplyict.com.au/monitoring-api `
  -SiteId site-benowa-elc `
  -SiteName "Benowa ELC" `
  -AgentId probe-benowa-nuc-01 `
  -Subnet 192.168.1.0/24
```

The script automatically:
1. Downloads NSSM (Non-Sucking Service Manager)
2. Creates `C:\Program Files\Mission Probe\current\`
3. Sets up a Python virtualenv
4. Writes config to `C:\ProgramData\mission-probe\env.ps1`
5. Registers `mission-probe` as a Windows service (auto-start)
6. Starts the service

Logs are written to `C:\Program Files\Mission Probe\logs\`.

### Supabase Backup
Runs daily at 02:00 UTC. Backups stored in `~/supabase-backups/`, 30-day retention.
```bash
python3 ~/supabase_backup.py          # manual run
systemctl status supabase-backup.timer
```

---

## Testing

### Integration Test Suite

`scripts/test_audit_integration.py` — 65 integration tests covering the full audit reporting pipeline.

**Run:**
```bash
cd /home/aiagent/mission-control-ui
source venv/bin/activate
python3 ~/mission-control-repo/scripts/test_audit_integration.py
```

**Test categories:**

| Category | Tests | What it covers |
|---|---|---|
| Helper Functions | 7 | Date formatting (AU `DD/MM/YYYY`), HTML escaping, boolean parsing |
| Classify Logic | 9 | All status paths — missing, weak PIN, password, breach, old photos, high photo count, compliant, ignored, custom thresholds |
| Build Report | 10 | Required keys, summary consistency, computed status on every row, section counts, recommendations |
| Score & Risk | 6 | Boundary values (0–100), perfect/bad/mixed scenarios, risk label mapping |
| PDF HTML Rendering | 11 | All section headings present, f-string interpolation, table row counts, room coverage, N/A ratio, policy checklist |
| PDF File Generation | 2 | Valid PDF output, filename convention (`{site}-{date}-executive.pdf`) |
| API Endpoints | 10 | GET batches/report/entries/PDF/sites, filtering, 404 handling, remediation summary |
| Data Completeness | 5 | Required fields populated (device_type, serial, room, present), field coverage tracking |
| Edge Cases | 5 | Empty entries, empty reports, fallback values, status pill HTML |

### Data Completeness Findings (June 2026)

The test suite tracks per-batch field coverage. Current findings for the active sites:

**Benowa ELC** (latest batch — 42 devices):

| Field | Populated | Coverage |
|---|---|---|
| device_type, serial_number, room | 42/42 | 100% |
| device_present | 42/42 | 100% |
| onedrive_sync_on / camera_sync_off | 36/42 | 86% |
| breach_notes / notes | 22/42 | 52% |
| windows_os / ios_version | 21/42 | 50% |
| security_check | 18/42 | 43% |
| photos_count | 13/42 | 31% |
| photos_date | 10/42 | 24% |
| brand_model | 0/42 | 0% |

**Benowa Hills ELC** (latest batch — 33 devices):

| Field | Populated | Coverage |
|---|---|---|
| device_type, serial_number, room | 33/33 | 100% |
| device_present | 33/33 | 100% |
| All other fields | 0/33 | 0% |

**Key gaps:**
- `brand_model` is never populated — device make/model is not collected by the audit form
- Benowa Hills has no detail data beyond device registration — auditor did not fill in OS, photos, sync, or security fields
- Photo counts and dates are only captured for ~31% of Benowa ELC devices

**Mitigation deployed:**
- Audit form (`device-audit.html`) now shows a **Data completeness column** per row (✅ Complete / ⚠️ 3/6 / ❌ Empty) based on expected fields per device type
- **Save All Rows** button added to streamline bulk saves
- `brand_model` field should be added to the audit form or populated from the device register

---

## Repository Structure

```
mission-control/
├── README.md
├── CHANGELOG.md
├── autopush.sh               # nightly git commit + push script
├── supabase_backup.py        # daily Supabase table export
├── scripts/
│   ├── test_audit_integration.py  # 65 integration tests (PDF, API, data)
│   ├── release_evidence_bundle.py
│   └── ...
├── ui/
│   ├── app.py                # Flask auth proxy (2FA, brute-force, sessions)
│   ├── device_audit_api.py   # FastAPI audit + governance API
│   ├── pdf_report_generator.py
│   ├── requirements.txt
│   ├── mission-control-ui.service
│   ├── director-view.html    # Governance + director dashboard
│   ├── site-onboarding.html  # ACECQA policy configuration
│   ├── incident-register.html
│   ├── remediation.html
│   ├── device-records.html
│   ├── device-audit.html
│   ├── audit-report-view.html
│   ├── 2fa-setup.html
│   ├── 2fa-verify.html
│   └── ...
├── site/                     # Monitoring backend + probe agent
│   ├── backend_api.py        # FastAPI monitoring API (port 8000)
│   ├── mission_probe/        # Pip-installable probe agent package
│   │   ├── scanner.py        # Network discovery
│   │   ├── enrichment.py     # MAC/device type enrichment
│   │   ├── client.py         # Backend API client
│   │   ├── updater.py        # Self-update mechanism
│   │   └── deploy/           # systemd unit + install scripts (Linux + Windows)
│   ├── device_patterns.py    # DB-backed device pattern analysis
│   ├── notify.py             # Alert notification dispatch
│   └── archive/              # Historical backend API versions
├── deploy/                   # Production systemd units
│   └── backend-api.service
```

---

## Version History

See [CHANGELOG.md](CHANGELOG.md).

**Current**: v1.0 — June 2026