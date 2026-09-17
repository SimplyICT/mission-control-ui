# Changelog — Mission Control ACECQA Compliance Platform

All notable changes to this project are documented here.

---

## [v1.4] — 2026-09-17

Released agent version: **1.1.2** (`AGENT_VERSION` in `agent_unified.py`).

**Verified in production** on a real client machine (DESKTOP-37759RK): installer
push took it 1.1.0 → 1.1.1, then a pushed `self_update` took it 1.1.1 → 1.1.2
(telemetry `update {from: 1.1.1, to: 1.1.2, success: true}`, agent back online on
1.1.2 within seconds). The re-delivered command then self-limited with
"payload version 1.1.2 is not newer than 1.1.2".

### Added — SOC agent auto-update (roadmap P1.1)
- **One published artifact.** `GET /api/agent/download/agent?platform=<os>` serves
  `agent_unified.py` with `X-Agent-Version` + `X-Agent-Sha256` and `no-store`;
  `/api/agent/download/windows` stays as the installer/back-compat path with the
  same headers.
- **Version derived from the agent file.** `soc_api.agent_meta()` reads
  `AGENT_VERSION` and the sha256 straight out of `agent_unified.py` (mtime-cached),
  so a release is a one-line version bump — no second constant to keep in sync.
- **Registration ack carries everything needed to update**: `latest_version`,
  `agent_sha256`, `download_url` built from the address the agent actually reached
  us on (mesh / LAN / public all work), and a semver `needs_update`.
- **Agent-side update is verify-before-replace**: download → sha256 check → parse the
  payload's `AGENT_VERSION` and refuse equal/older → syntax-compile the payload →
  keep a `.bak` → `os.replace` (atomic) → report the outcome over the WS
  (`{"type":"update"}`) → re-exec. One attempt per process; failures leave the
  running agent untouched. The same path serves the pushed `self_update` command
  and polling-mode agents (`POST /api/agent/{id}/poll` now answers with the update
  hint when it has no queued command).
- **Outbox delivery tracking**: delivered commands are marked `sent`, so the drain
  loop no longer re-sends the same command every 5s; unanswered commands are
  re-delivered on reconnect (`pending_commands(include_sent=True)`).
- New bulk/partial update endpoint shape: `POST /api/agents/update` accepts
  `agent_ids`, `all`, or `outdated` and reports `{updated, failed, targets,
  latest_version}`.
- `/api/agents/all` and `/api/agents/online` now report `needs_update`,
  `latest_version`, `update` (last report) and `update_requested_at`, with status
  resolved from the live WS set plus a 10-minute check-in window (the SPA's
  offline filter was counting every agent as offline before this).

### Fixed
- **Handlers defined after the `__main__` guard never registered.** `main()` sat
  mid-file, so `eventlog`, `forward_logs`, `self_update`, `fim_scan`, `packages`
  and `vuln_packages` were missing from `HANDLERS` whenever the agent ran as a
  script (always). Server-pushed commands for those handlers — including the
  update command and every queued FIM/vulnerability scan — were silently ignored.
  The guard now lives at the end of the file; all 14 handlers register.
- **On-connect update was dead.** The ack handler referenced `_aiohttp`/`_json`,
  which are only bound when aiohttp is *missing*, so every agent raised
  `NameError: name '_aiohttp' is not defined` and skipped the update. Replaced with
  `_await_registered()` (waits for the ack, queues any earlier command frames for
  the main loop) plus the shared verified update path.

---

## [v1.3] — 2026-09-04

### Added — Action Tier Engine (AI-Everywhere Phase 2)
- Tier classification in `ai_remediate.py` (`ACTION_TIERS` + `classify_case`):
  Tier 1 = reversible/contained/informational (notify, watchlist, suppress,
  ping, review/investigate steps); Tier 2 = major change (block_ip, isolate,
  revoke, MFA/tenant changes, deletes, patches). Unknown actions default to
  Tier 2 (conservative). Informational step prefixes are Tier 1.
- `execute_case(case, tier=None, dry_run=False)`: tier-filtered execution and
  a dry-run preview with per-action rollback notes.
- Autopilot scanner now auto-executes Tier-1 actions at case creation with an
  audit trail (`tier1_auto_executed`); the old branch that auto-executed the
  ENTIRE plan for level≥15/confidence≥0.9 (including destructive actions) is
  removed. Tier-2 actions wait for human approval.
- `POST /api/autopilot/cases/{id}/execute` is now a real background task:
  gated to approved cases, returns a dry-run preview with rollback guidance,
  runs the Tier-2 remainder after approval, and records results/events.
- Unknown plan actions with a target are skipped with a human-review note
  instead of silently pinging the target.

### Fixed
- `add_watchlist` plan actions were dropped by the executor (dispatch key
  mismatch) — now executed.

---

## [v1.0] — 2026-06-03

### Added

#### Auth & Security
- Session-based login with brute-force lockout (5 attempts → 15-min block)
- Cloudflare `X-Forwarded-For`-aware IP detection for accurate rate limiting
- TOTP 2FA via pyotp — QR code setup, activate/disable per user, admin reset
- `2fa-setup.html` and `2fa-verify.html` UI pages
- All protected routes gated behind both password and 2FA checks

#### Device Audit API (`device_audit_api.py`)
- Site-aware `classify()` — photo retention days and count thresholds per site
- `build_rows()` propagates site thresholds to every entry
- `build_report()` — audit summary with KPIs, recommendations
- `GET /director-dashboard` — rewritten with 3 bulk Supabase `IN` queries (was N×3 = 55s; now 2.4s)
- `GET /governance-summary` — remediations, incidents, policy, NQS mapping, per-site policy breakdown, audit recency
- `GET /devices/export.csv` — 26-column device export
- `POST /devices/import` — CSV upsert on `device_id`
- `POST /devices/create` — single device creation
- `DELETE /incidents/{id}` — incident deletion
- `remediation.by_priority` and `incidents.by_severity` breakdowns
- `policy.by_site` — per-site confirmed/gap/missing policy breakdown with real site names
- `audit_recency` — latest audit age per site, overdue flag >90 days, sorted most-overdue first

#### Governance Dashboard (`director-view.html`)
- 11 KPI tiles: remediations open/overdue/resolved, critical/high priority, incidents open/mandatory/critical/high, policy gaps, sites policy-complete
- Per-Site Policy Compliance table (confirmed/9, gaps, not-set, missing policy names)
- Audit Recency table (date, age, overdue flag, colour-coded)
- NQS Quality Area mapping (NQS 2.2, 7.1, 7.2)
- "Refresh All" button updates both director and governance data
- Governance timestamp showing last loaded time

#### Site Onboarding (`site-onboarding.html`)
- 9 ACECQA policy toggles per site
- Audit frequency and photo retention threshold fields
- Save/load via API on page open

#### Incident Register (`incident-register.html`)
- Delete button with confirmation per row
- Mandatory-reportable flagging, severity levels

#### Infrastructure
- SSL via Let's Encrypt on `audit.simplyict.com.au`
- `mc-autopush.timer` — nightly git commit and push to GitHub
- `supabase-backup.timer` — daily 02:00 UTC export to `.tar.gz`, 30-day retention
- `supabase_backup.py` — exports 6 tables with pagination

#### PDF Reports (`pdf_report_generator.py`)
- Policy Compliance Checklist section with per-site score and thresholds
- Cover page shows `audit_frequency` and `policy_confirmed/total`
- Executive summary KPI box for policy checklist

### Changed
- `director-dashboard` response time: 55.9s → 2.4s (23× faster)
- Navigation links converted to relative paths (works behind nginx prefix)
- Root `/` route serves `index-platform.html`
- `/api/services-health` proxy endpoint for service status cards

### Security
- `.env` excluded from git via `.gitignore`
- `users.json` excluded from git
- SSH deploy key at `~/.ssh/id_ed25519`

---

## [v1.2] — 2026-09-02

### Changed
- Authentication now trusts Cloudflare Access at the edge: requests carrying a valid
  `Cf-Access-Jwt-Assertion` (validated against the team JWKS, audience-checked for
  audit/mc.simplyict.com.au) are authenticated automatically — no second app login.
  Direct origin requests (e.g. `:8095`) that bypass Cloudflare still fall back to the
  app login page until authenticated.

## [v1.1] — 2026-06-20

### Added
- Help and DevDocs pages (`help.html`, `devdocs.html`) with usage guide, API docs, and troubleshooting
- Help and DevDocs buttons added to all 56+ monitoring and audit UI pages
- Project Hub: restored 8 build project trackers (SimplyClik, SOC projects, SEO, Mission Control repos) from legacy data

### Fixed
- Site dropdown deduplication: backend API now filters duplicate sites by name and removes test entries
- Project Hub: restored missing projects from old `project-manager.html` data source
- Project Hub: test project now persists through API (not direct file writes that get overwritten)

## [Initial] — 2026-05 — `fb700f5`

Base Mission Control platform — device audit, site management, audit report viewer, remediation and incident UI scaffolding. Supabase backend, FastAPI + Flask stack.