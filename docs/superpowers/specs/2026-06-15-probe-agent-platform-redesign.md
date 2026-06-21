# Mission Control Probe Agent Platform — Production-Grade Redesign

**Date:** 2026-06-15
**Status:** Draft
**Author:** AI-assisted design

## Overview

Redesign the site probe agent system from a loose collection of scripts into a production-grade agent platform. The probe agent runs on an Intel NUC (or similar) at each client site, performs periodic ARP + ICMP discovery of the local subnet, and reports device state to the central Mission Control backend. The redesign covers agent packaging/deployment, backend performance, agent lifecycle management, and code quality.

## Architecture Decisions

- **Agent packaging**: pip-installable Python package (`mission-probe`) with systemd service unit, removing the "copy the script manually" pattern
- **Agent self-update**: Poll a backend release endpoint — no truck roll needed for version upgrades
- **Backend batch ingestion**: Replace N+1 Supabase REST calls with batch upsert (PostgREST bulk + PostgreSQL function), reducing ~400 HTTP calls per scan cycle to 2
- **Data model**: Migrate `text`-typed JSON columns (`metadata`, `raw`) to `jsonb` for queryability
- **Agent health alerting**: Server-side staleness detection with dedicated `AGENT_MISSING` alert type
- **Device patterns**: Migrate from local JSON file to database table for resilience
- **Rate limiting**: In-memory token bucket for agent-facing endpoints

## Components & Data Flow

### Current Flow (per 60s cycle, per agent)

```
Agent: scan_subnet() → 200+ devices
  → POST /api/v1/heartbeat                      (1 HTTP call)
  → POST /api/v1/devices/report                  (1 HTTP call)
    → Backend: for each device:
        → GET mc_network_devices (find by MAC/IP) (N HTTP calls)
        → PATCH/POST mc_network_devices          (N HTTP calls)
        → POST mc_device_observations            (N HTTP calls)
    → sweep_offline_devices()                    (M HTTP calls)
Total: ~400 HTTP calls per cycle per site
```

### Target Flow

```
Agent: scan_subnet() → 200+ devices
  → POST /api/v1/heartbeat                      (1 HTTP call)
  → POST /api/v1/devices/report                  (1 HTTP call)
    → Backend: 
        → SELECT rpc.upsert_devices(jsonb)       (1 Supabase RPC call)
        → SELECT rpc.bulk_insert_observations()  (1 Supabase RPC call)
        → SELECT rpc.sweep_offline_devices()     (1 Supabase RPC call)
Total: 4 HTTP calls per cycle per site
```

## Detailed Design

### 1. Backend — Batch Ingestion

#### 1.1 PostgreSQL Functions

Create Supabase database functions for bulk operations:

```sql
-- Upsert devices in a single transaction
CREATE FUNCTION public.upsert_devices(
  p_site_id UUID,
  p_agent_id UUID,
  p_devices JSONB
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_inserted INT := 0;
  v_updated INT := 0;
  v_seen_ids UUID[] := '{}';
  v_device JSONB;
  v_device_id UUID;
BEGIN
  FOR v_device IN SELECT * FROM jsonb_array_elements(p_devices) LOOP
    INSERT INTO public.mc_network_devices (
      site_id, last_seen_by_agent_id, ip_address, mac_address,
      hostname, vendor, device_type, friendly_name,
      status, last_seen_at, last_online_at, last_latency_ms,
      expected_online, updated_at
    ) VALUES (
      p_site_id, p_agent_id,
      v_device->>'ip_address', v_device->>'mac_address',
      v_device->>'hostname', v_device->>'vendor',
      v_device->>'device_type', v_device->>'friendly_name',
      COALESCE(v_device->>'status', 'ONLINE'), NOW(),
      CASE WHEN v_device->>'status' = 'ONLINE' THEN NOW() ELSE NULL END,
      (v_device->>'latency_ms')::numeric,
      TRUE, NOW()
    )
    ON CONFLICT (site_id, mac_address) WHERE mac_address IS NOT NULL DO UPDATE SET
      ip_address = EXCLUDED.ip_address,
      hostname = EXCLUDED.hostname,
      vendor = EXCLUDED.vendor,
      device_type = EXCLUDED.device_type,
      friendly_name = EXCLUDED.friendly_name,
      status = EXCLUDED.status,
      last_seen_at = EXCLUDED.last_seen_at,
      last_online_at = EXCLUDED.last_online_at,
      last_latency_ms = EXCLUDED.last_latency_ms,
      last_seen_by_agent_id = EXCLUDED.last_seen_by_agent_id,
      updated_at = EXCLUDED.updated_at
    RETURNING id INTO v_device_id;

    v_seen_ids := array_append(v_seen_ids, v_device_id);
  END LOOP;

  RETURN jsonb_build_object(
    'status', 'ok',
    'seen_device_ids', to_jsonb(v_seen_ids)
  );
END;
$$;
```

```sql
-- Bulk insert observations
CREATE FUNCTION public.bulk_insert_observations(
  p_observations JSONB
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_count INT := 0;
BEGIN
  INSERT INTO public.mc_device_observations (
    site_id, agent_id, device_id, observed_at,
    ip_address, mac_address, hostname, status,
    latency_ms, packet_loss_percent, method, raw
  )
  SELECT
    (item->>'site_id')::UUID,
    (item->>'agent_id')::UUID,
    (item->>'device_id')::UUID,
    COALESCE((item->>'observed_at')::TIMESTAMPTZ, NOW()),
    item->>'ip_address',
    item->>'mac_address',
    item->>'hostname',
    COALESCE(item->>'status', 'ONLINE'),
    (item->>'latency_ms')::numeric,
    (item->>'packet_loss_percent')::numeric,
    item->>'method',
    (item->>'raw')::jsonb
  FROM jsonb_array_elements(p_observations) AS item;

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN jsonb_build_object('inserted', v_count);
END;
$$;
```

```sql
-- Offline sweep as a single query
CREATE FUNCTION public.sweep_offline_devices(
  p_site_id UUID,
  p_seen_device_ids UUID[],
  p_offline_after_seconds INT DEFAULT 180
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_marked INT := 0;
BEGIN
  UPDATE public.mc_network_devices
  SET status = 'OFFLINE',
      last_offline_at = NOW(),
      updated_at = NOW()
  WHERE site_id = p_site_id
    AND expected_online = TRUE
    AND status NOT IN ('OFFLINE', 'DISABLED')
    AND last_seen_at < NOW() - (p_offline_after_seconds || ' seconds')::INTERVAL
    AND id != ALL(p_seen_device_ids);

  GET DIAGNOSTICS v_marked = ROW_COUNT;
  RETURN jsonb_build_object('marked_offline', v_marked);
END;
$$;
```

#### 1.2 New Backend Endpoints

```
POST /api/v1/agent/release      → Returns latest agent version + download URL
GET  /api/v1/agent/releases     → Lists available versions (admin)
POST /api/v1/agent/releases     → Upload new agent release (admin)
```

#### 1.3 Rate Limiting

Add `slowapi` middleware or lightweight in-memory token bucket:

- Per-agent-key rate limit: 12 requests/min (3× headroom above the 2/min normal rate)
- Rate limit on `/api/v1/devices/report`: 6/min per agent key
- Rate limit on `/api/v1/heartbeat`: 6/min per agent key
- Return `429 Too Many Requests` with `Retry-After` header

### 2. Agent — `mission-probe` Package

#### 2.1 Package Structure

```
site/mission_probe/
├── __init__.py
├── __main__.py          # python -m mission_probe entry
├── main.py              # Main loop, signal handling
├── config.py            # Env var + config file loader
├── scanner.py           # Subnet scan (ping + ARP)
├── enrichment.py        # Vendor guess, hostname, device type
├── client.py            # API client (heartbeat, report, update check)
├── updater.py           # Self-update orchestration
└── deploy/
    ├── mission-probe.service     # systemd unit
    ├── install.sh               # Linux install script
    └── config.toml.example      # Example config
```

#### 2.2 Config Loading

Priority: CLI args > env vars > config file > defaults

Config file path: `/etc/mission-probe/config.toml`

```toml
[agent]
api_base = "https://audit.simplyict.com.au/monitoring-api"
api_key = "sk-..."
site_id = "site-benowa-elc"
site_name = "Benowa ELC"
agent_id = "probe-benowa-nuc-01"

[scan]
subnet = "192.168.1.0/24"
interval_seconds = 60
ping_timeout_seconds = 1
workers = 64

[detection]
offline_after_seconds = 180
enable_hostname_lookups = true

[update]
enabled = true
check_interval_cycles = 10  # Every 10 scan cycles
```

#### 2.3 Self-Update Flow

```
1. Every N scan cycles, agent calls GET /api/v1/agent/release?current=v8
2. Backend responds:
   {
     "upgrade_available": true,
     "version": "v9",
     "download_url": "/api/v1/agent/releases/v9/download",
     "checksum_sha256": "abc123...",
     "changelog": "...",
     "critical": false
   }
3. Agent downloads release, verifies SHA-256 checksum
4. Agent writes new version to /opt/mission-probe/next/
5. Agent validates the download (import check, version string)
6. Agent symlinks /opt/mission-probe/current → /opt/mission-probe/next/
7. Agent calls systemd restart on itself (service restarts, new version runs)
8. On startup, new version sends heartbeat with new version string
```

Backward compatibility: if update check fails (e.g., network down), agent continues with current version. If downloaded package is malformed, rollback to backup.

#### 2.4 Systemd Service

```ini
[Unit]
Description=Mission Control Site Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mission-probe
Group=mission-probe
ExecStart=/opt/mission-probe/current/venv/bin/python -m mission_probe
Restart=on-failure
RestartSec=10
EnvironmentFile=/etc/mission-probe/env
WorkingDirectory=/opt/mission-probe/current

[Install]
WantedBy=multi-user.target
```

#### 2.5 Agent Health

The agent sends a heartbeat every scan cycle. Heartbeat includes system metrics:

```python
{
  "site_id": "site-benowa-elc",
  "agent_id": "probe-benowa-nuc-01",
  "hostname": "nuc-01",
  "agent_version": "v8",
  "lan_ip": "192.168.1.100",
  "cpu_percent": 23.5,
  "memory_percent": 41.2,
  "disk_percent": 55.0,
  "uptime_seconds": 360000,
  "metadata": {
    "scan_subnet": "192.168.1.0/24",
    "last_scan_duration_ms": 12400,
    "devices_found": 187,
    "errors_last_cycle": 0
  }
}
```

### 3. Backend — Agent Health Alerting

In a background task (or triggered after each device report), check:

```sql
SELECT a.id, a.agent_key, a.site_id, a.last_heartbeat_at, s.site_code
FROM mc_probe_agents a
JOIN mc_sites s ON s.id = a.site_id
WHERE a.status != 'DISABLED'
  AND a.last_heartbeat_at < NOW() - INTERVAL '5 minutes'
  AND a.last_heartbeat_at > '2024-01-01'  -- Ignore agents that never connected
```

For each stale agent, create/update an `AGENT_MISSING` alert:

```python
create_or_touch_alert(
    site_uuid=site_id,
    alert_type="AGENT_MISSING",
    severity="HIGH",
    title=f"Probe agent offline: {agent_key}",
    message=f"Agent {agent_key} at {site_code} has not reported for X minutes.",
    fingerprint=f"{site_id}:AGENT_MISSING:{agent_id}",
)
```

### 4. Database Schema Changes

#### 4.1 Column Type Migrations

```sql
ALTER TABLE public.mc_probe_agents
  ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;

ALTER TABLE public.mc_network_devices
  ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;

ALTER TABLE public.mc_device_observations
  ALTER COLUMN raw TYPE jsonb USING raw::jsonb;

ALTER TABLE public.mc_alerts
  ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;

ALTER TABLE public.mc_probe_heartbeats
  ALTER COLUMN payload TYPE jsonb USING payload::jsonb;
```

#### 4.2 New Constraints and Indexes

```sql
-- Unique constraint for upsert
ALTER TABLE public.mc_network_devices
  DROP CONSTRAINT IF EXISTS uq_site_mac,
  ADD CONSTRAINT uq_site_mac UNIQUE NULLS NOT DISTINCT (site_id, mac_address);

-- Index for agent health queries
CREATE INDEX IF NOT EXISTS idx_mc_probe_agents_heartbeat
  ON public.mc_probe_agents(last_heartbeat_at DESC);
```

#### 4.3 Device Patterns Table

```sql
CREATE TABLE IF NOT EXISTS public.mc_device_patterns (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES public.mc_network_devices(id) ON DELETE CASCADE,
  last_offline_at TIMESTAMPTZ,
  offline_count_30d INT DEFAULT 0,
  first_seen_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ DEFAULT NOW(),
  offline_events JSONB DEFAULT '[]'::jsonb,
  online_events JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mc_device_patterns_device
  ON public.mc_device_patterns(device_id);
```

### 5. Code Cleanup

- Remove old agent versions: `site_probe_agent.py` through `site_probe_agent_v7_enrichment.py`
- Keep only `site/mission_probe/` package
- Remove `site/device_patterns.py` (replaced by DB table)
- Remove `site/device_patterns.json` (replaced by DB table)
- Update `README.md` with new architecture

## Implementation Plan

### Phase 1: Backend Performance (Tasks 1-4)

| Task | Description | Files | Est. |
|------|-------------|-------|------|
| 1 | DB schema migration: jsonb columns + constraints + indexes | `schema.sql`, Supabase SQL | S |
| 2 | Create PostgreSQL functions: upsert_devices, bulk_insert_observations, sweep_offline_devices | Supabase SQL | M |
| 3 | Rewrite `devices_report()` endpoint to use batch RPC calls | `site/backend_api.py` | M |
| 4 | Add rate limiting middleware | `site/backend_api.py` | S |

### Phase 2: Agent Lifecycle (Tasks 5-7)

| Task | Description | Files | Est. |
|------|-------------|-------|------|
| 5 | Agent release management endpoints | `site/backend_api.py` | M |
| 6 | Agent health alert background checker | `site/backend_api.py` | S |
| 7 | Migrate device_patterns to DB table | `site/backend_api.py`, `schema.sql` | S |

### Phase 3: Agent Package (Tasks 8-12)

| Task | Description | Files | Est. |
|------|-------------|-------|------|
| 8 | Create `mission_probe/` package skeleton, config loader, pyproject.toml | `site/mission_probe/*` | M |
| 9 | Port scanner logic into clean module | `site/mission_probe/scanner.py` | M |
| 10 | Port enrichment logic into clean module | `site/mission_probe/enrichment.py` | M |
| 11 | Implement API client + self-update mechanism | `site/mission_probe/client.py`, `updater.py` | M |
| 12 | Create systemd service + install script | `site/mission_probe/deploy/*` | S |

### Phase 4: Polish (Tasks 13-14)

| Task | Description | Files | Est. |
|------|-------------|-------|------|
| 13 | Add systemd unit for backend API (port 8000) | `deploy/backend-api.service` | S |
| 14 | Update README, deployment docs, clean up old files | `README.md`, `site/` cleanup | S |

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| PostgREST RPC function timing out for large payloads | High | Set client timeout to 30s; functions use batch processing with RETURNING |
| Agent self-update breaks on Windows | Medium | Keep Windows fallback as script-based install; self-update is Linux-first |
| Schema migration fails on existing text data (malformed JSON) | High | Test with `SELECT metadata::jsonb FROM mc_probe_agents LIMIT 10` first; use `ALTER COLUMN ... USING` with try/catch |
| Rate limiting blocks legitimate agent traffic | Medium | Start with generous limits (12/min), monitor and tighten |
| Agent restart during scan loses that cycle's data | Low | Cycle completes before update check; update is deferred by 1 cycle if scan is in progress |

## Open Questions

- Should the PostgreSQL functions live in `schema.sql` or be applied separately via migration?
- What CDN strategy for agent release downloads? (Serve from Supabase storage? From nginx static?)
- Windows agent support: PyInstaller bundle or keep as raw Python script?
