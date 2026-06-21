# Audit Resume, Finalize, and Re-open

## Problem

When creating an audit batch, users have no way to:
- Resume an audit that was interrupted (e.g., laptop battery died mid-audit)
- Mark an audit as complete/finalized
- Re-open a finalized audit to make changes

## Data Model

Add `status` column to `device_audits` table:
- Type: `text`
- Default: `"in_progress"`
- Values: `"in_progress"` | `"finalized"`
- Informational only — does not lock or block any editing

## API Changes

### New Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/audits/resume/{site_id}` | List in-progress audit batches for a site (id, date, entry count, created_at) |
| `POST` | `/audits/{audit_batch_id}/finalize` | Set status to `"finalized"` |
| `POST` | `/audits/{audit_batch_id}/reopen` | Set status back to `"in_progress"` |

### Modified Endpoints

| Endpoint | Change |
|---|---|
| `POST /audits/start` | Set `status: "in_progress"` on created batch |
| `GET /audit-batches` | Include `status` field in response |
| `GET /audit-entries/{audit_batch_id}` | Include batch `status` in response |

## UI Changes

### Run Audit Page (`device-audit.html`)

After selecting a site:
1. Call `GET /audits/resume/{site_id}`
2. If in-progress audits exist, show "Resume Audit" panel above the form:
   - Cards/rows showing audit date, entry count, last modified
   - "Resume" button → loads that batch's entries into the editor
   - "Start New Audit" button below
3. If no in-progress audits exist, show "Start New Audit" as before

In the audit editor header (after loading a batch):
- Status badge: "In Progress" (blue) or "Finalized" (green)
- "Finalize Audit" button (when `in_progress`) → confirms, calls finalize API, updates badge
- "Re-open Audit" button (when `finalized`) → confirms, calls reopen API, updates badge

### Audit Reports Page (`audit-reports.html`)

In the batches table:
- New "Status" column with badge: "In Progress" (blue) or "Finalized" (green)
- New "Actions" column:
  - "Finalize" button for in_progress batches
  - "Re-open" button for finalized batches
- Buttons call respective APIs and refresh the table

### Audit Report View (`audit-report-view.html`)

- Show status badge in the report header (read-only display)

## Files Modified

1. `device_audit_api.py` — 3 new endpoints + modify existing endpoints
2. `device-audit.html` — Resume panel, status badge, Finalize/Re-open buttons
3. `audit-reports.html` — Status column, Finalize/Re-open buttons

## Verification

- Creating a new audit sets status to `"in_progress"`
- Run Audit page shows in-progress audits on site selection
- Resuming loads the correct batch entries
- Finalizing updates status, reflected in UI
- Re-opening restores `in_progress` status
- Audit Reports page shows correct status and action buttons
