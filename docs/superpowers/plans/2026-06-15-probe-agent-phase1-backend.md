# Phase 1: Backend Performance — Implementation Plan

> Based on spec: `docs/superpowers/specs/2026-06-15-probe-agent-platform-redesign.md`

**Goal:** Replace N+1 Supabase REST calls in `devices_report` with batch PostgreSQL functions, add rate limiting, and migrate text columns to jsonb.

## Task List

### Task 1: DB Schema Migration (jsonb + constraints + indexes)

**Description:** Run SQL migration to convert text-typed JSON columns to jsonb, add unique constraint on (site_id, mac_address), and add performance indexes.

**Acceptance criteria:**
- [ ] All `text` columns that store JSON are migrated to `jsonb`
- [ ] `uq_site_mac` unique constraint exists on `mc_network_devices(site_id, mac_address)`
- [ ] Index `idx_mc_probe_agents_heartbeat` exists

**Verification:**
- [ ] SQL runs without errors in Supabase SQL editor
- [ ] `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'mc_network_devices'` shows jsonb for metadata column
- [ ] Existing data is preserved

**Files likely touched:**
- `docs/superpowers/specs/2026-06-15-probe-agent-platform-redesign.md` (embedded SQL) or a standalone `.sql` file

---

### Task 2: Create PostgreSQL Functions

**Description:** Create three Supabase database functions for bulk operations: `upsert_devices`, `bulk_insert_observations`, `sweep_offline_devices`. These run in a single transaction and replace the N+1 pattern.

**Acceptance criteria:**
- [ ] `upsert_devices(p_site_id UUID, p_agent_id UUID, p_devices JSONB)` exists and returns JSONB
- [ ] `bulk_insert_observations(p_observations JSONB)` exists and returns JSONB
- [ ] `sweep_offline_devices(p_site_id UUID, p_seen_device_ids UUID[], p_offline_after_seconds INT)` exists and returns JSONB
- [ ] All functions are created in the `public` schema

**Verification:**
- [ ] Query `SELECT * FROM pg_proc WHERE proname IN ('upsert_devices', 'bulk_insert_observations', 'sweep_offline_devices')` returns 3 rows
- [ ] Test with sample JSONB data returns expected structure

**Files likely touched:**
- `schema.sql` or run in Supabase SQL editor

---

### Task 3: Rewrite `devices_report` Endpoint with Batch RPC

**Description:** Rewrite the `POST /api/v1/devices/report` endpoint to call the three PostgreSQL functions via PostgREST RPC instead of per-device REST calls. This collapses ~400 HTTP calls per cycle into 2-3.

**Acceptance criteria:**
- [ ] `devices_report` calls `rpc.upsert_devices()` with the full device list as JSONB
- [ ] `devices_report` calls `rpc.bulk_insert_observations()` with the full observations list as JSONB
- [ ] `devices_report` calls `rpc.sweep_offline_devices()` with the seen device IDs
- [ ] Alert logic (DEVICE_BACK_ONLINE, DEVICE_OFFLINE, fingerprint dedup) is preserved
- [ ] Same response schema returned

**Verification:**
- [ ] Test with 2+ devices — only 3 Supabase HTTP calls made (observable via logs)
- [ ] Devices are correctly upserted (updates existing MAC, inserts new)
- [ ] Observations are correctly inserted
- [ ] Offline sweep marks unseen devices as OFFLINE
- [ ] Alert creation still fires for status transitions

**Files likely touched:**
- `site/backend_api.py` (modify `devices_report` at line 671)

---

### Task 4: Add Rate Limiting Middleware

**Description:** Add in-memory token bucket rate limiting to agent-facing endpoints to prevent abuse.

**Acceptance criteria:**
- [ ] Per-agent-key rate limit: 12 requests/min
- [ ] Rate limit on `POST /api/v1/devices/report`: 6/min per agent key
- [ ] Rate limit on `POST /api/v1/heartbeat`: 6/min per agent key
- [ ] Returns `429 Too Many Requests` with `Retry-After` header when exceeded

**Verification:**
- [ ] Send 7 rapid requests to `/api/v1/devices/report` — 6th+ returns 429
- [ ] `Retry-After` header present in 429 response
- [ ] Normal traffic (2 req/min) never hits rate limit

**Files likely touched:**
- `site/backend_api.py` (add middleware or dependency)

---

## Dependencies

```
Task 1 (schema migration) ──┐
                             ├── Task 3 (rewrite endpoint)
Task 2 (PG functions) ──────┘
                                 
Task 4 (rate limiting) ───── independent, can be done in parallel
```

## Verification Checkpoint (after all Phase 1 tasks)

- [ ] `devices_report` handles 200 devices in under 5 seconds (was likely 30+ seconds)
- [ ] Supabase REST call count per cycle drops from ~400 to ~5
- [ ] Rate limiting blocks excessive requests correctly
- [ ] Existing alerts and device status tracking still works
- [ ] `systemctl restart mission-control-api.service` succeeds and agent reconnects
