# Probe Agent Data Showcase

**Date:** 2026-06-16
**Status:** Draft

## Problem

The probe agent scanner collects rich data (device status, latency, observations, vendor, type, metadata) but most of it is invisible in the current UI. Only the Live Dashboard shows observations. Latency, metadata, device detail drill-down, historical trends, and export are missing from every surface.

## Goals

1. Surface data the scanner already collects but isn't shown
2. Add analytical views (trends, sparklines, timelines)
3. Enable export and reporting
4. Integrate probe data with audit compliance context

## Phases

### Phase 1 — Surface Existing Data (quick wins)

| # | Task | What |
|---|------|------|
| 1 | Device detail page | New HTML page consuming `/api/v1/dashboard/device/{id}` — shows full device profile, observation history, alert history |
| 2 | Latency display | Render `last_latency_ms` on device rows across all dashboards, flag high-latency (>10ms) |
| 3 | Observation timeline on Exec Dashboard | Add recent observation counts and status timeline to Executive Dashboard |
| 4 | CSV export | New `/api/v1/devices/export/csv` endpoint + download button |
| 5 | Device metadata/tags | Show `metadata` jsonb fields and `tags` in Device Admin view |

### Phase 2 — Analytics & Trends

| # | Task | What |
|---|------|------|
| 6 | Availability charts | Per-device and per-site availability % over configurable time ranges (24h, 7d, 30d) |
| 7 | Latency sparklines | Mini sparkline per device showing last N observations latency trend |
| 8 | Activity feed | Reverse-chronological feed of device state changes (offline→online, new device detected, status changes) |
| 9 | Per-device timeline | Full timeline view with observations, status changes, alerts overlaid |

### Phase 3 — Advanced

| # | Task | What |
|---|------|------|
| 10 | Real-time push via SSE | Device events pushed to dashboards instead of polling |
| 11 | Scheduled uptime reports | Monthly/quarterly PDF uptime report per site |
| 12 | Audit cross-reference | Link probe device uptime/availability to ACECQA compliance evidence |
| 13 | Connectivity topology | Visual map of device relationships on the network |

## Architecture

- **No backend changes needed for Phase 1** (APIs already exist)
- Phase 2 may require new aggregation endpoints (availability calculations, activity feed)
- Phase 3 requires new backend work (SSE event emission, PDF generation, topology inference)

## Success Criteria

- A user can click any device in any dashboard and see its full history
- Latency data is visible and actionable across all dashboards
- Export produces a usable CSV of current device state
- Availability trends are visible at both device and site level within 2 clicks
