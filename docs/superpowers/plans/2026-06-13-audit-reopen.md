# Audit Resume, Finalize, and Re-open Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add audit status tracking (`in_progress`/`finalized`), resume in-progress audits from the Run Audit page, finalize audits when complete, and re-open finalized audits.

**Architecture:** Add `status` column to `device_audits` (default `"in_progress"`). Three new API endpoints (resume list, finalize, reopen). UI shows resume panel on site selection in device-audit.html, status badge + action buttons on both device-audit.html and audit-reports.html. Status is informational — no editing locks.

**Tech Stack:** FastAPI (Python), Supabase (Postgres), vanilla HTML/JS

---

### Task 0: Database — Add `status` column to `device_audits` table

**Files:**
- N/A (run in Supabase dashboard or via SQL)

- [ ] **Step 1: Add status column with default value**

Run this SQL in the Supabase SQL editor:

```sql
ALTER TABLE device_audits ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'in_progress';
```

This sets all existing records to `'in_progress'` and ensures new records default to `'in_progress'` even if not explicitly provided.

---

### Task 1: API — Add status to start_audit endpoint

**Files:**
- Modify: `device_audit_api.py:1362-1372`

- [ ] **Step 1: Add `"status": "in_progress"` to audit_payload in start_audit**

In `device_audit_api.py` at line 1366, add `"status": "in_progress"` to the `audit_payload` dict:

```python
audit_payload = {
    "site_id": site["site_id"],
    "site_name": site["site_name"],
    "audit_date": date.today().isoformat(),
    "audit_type": "Device Audit",
    "report_generated": False,
    "status": "in_progress",
}
```

---

### Task 2: API — Add resume endpoint (list in-progress audits for a site)

**Files:**
- Modify: `device_audit_api.py` (add new endpoint after `get_audit_batches` around line 1194)

- [ ] **Step 1: Add GET /audits/resume/{site_id} endpoint**

Add after the `get_audit_batches` function (after line 1194):

```python
@app.get("/audits/resume/{site_id}")
def get_resume_audits(site_id: str):
    batches = (
        supabase.table("device_audits")
        .select("*")
        .eq("site_id", site_id)
        .eq("status", "in_progress")
        .order("audit_date", desc=True)
        .execute()
        .data
        or []
    )
    # Attach entry count for each batch
    result = []
    for b in batches:
        count = (
            supabase.table("audit_entries")
            .select("audit_id", count="exact")
            .eq("audit_batch_id", b["audit_batch_id"])
            .execute()
        )
        entry_count = count.count if hasattr(count, "count") else 0
        b["entry_count"] = entry_count
        result.append(b)
    return result
```

---

### Task 3: API — Add single-batch fetch endpoint

**Files:**
- Modify: `device_audit_api.py` (add after the resume endpoint)

- [ ] **Step 1: Add GET /audit-batch/{audit_batch_id} endpoint**

```python
@app.get("/audit-batch/{audit_batch_id}")
def get_single_audit_batch(audit_batch_id: str):
    return get_audit_batch(audit_batch_id)
```

This reuses the existing `get_audit_batch()` helper and returns the full batch record including `status`.

---

### Task 4: API — Add finalize endpoint

**Files:**
- Modify: `device_audit_api.py` (add after the resume endpoint)

- [ ] **Step 1: Add POST /audits/{audit_batch_id}/finalize endpoint**

```python
@app.post("/audits/{audit_batch_id}/finalize")
def finalize_audit(audit_batch_id: str):
    result = (
        supabase.table("device_audits")
        .update({"status": "finalized"})
        .eq("audit_batch_id", audit_batch_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Audit batch not found")
    return {"success": True, "status": "finalized", "audit_batch_id": audit_batch_id}
```

---

### Task 5: API — Add reopen endpoint

**Files:**
- Modify: `device_audit_api.py` (add after finalize endpoint)

- [ ] **Step 1: Add POST /audits/{audit_batch_id}/reopen endpoint**

```python
@app.post("/audits/{audit_batch_id}/reopen")
def reopen_audit(audit_batch_id: str):
    result = (
        supabase.table("device_audits")
        .update({"status": "in_progress"})
        .eq("audit_batch_id", audit_batch_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Audit batch not found")
    return {"success": True, "status": "in_progress", "audit_batch_id": audit_batch_id}
```

---

### Task 6: UI — device-audit.html — Add resume panel on site select

**Files:**
- Modify: `device-audit.html`

- [ ] **Step 1: Add HTML for resume panel**

Insert after the `siteStatus` paragraph (after line 206):

```html
<div id="resumePanel" style="display:none; margin-top:12px; border:1px solid #334155; border-radius:10px; padding:12px; background:#0f172a;">
  <h3 style="margin:0 0 8px 0; font-size:14px; color:#93c5fd;">Resume In-Progress Audit</h3>
  <div id="resumeList" style="display:flex; flex-direction:column; gap:6px;"></div>
  <hr style="border-color:#334155; margin:10px 0;">
  <button onclick="startAudit()" style="background:#2563eb;">Start New Audit</button>
</div>
```

- [ ] **Step 2: Add CSS for resume items**

Add to the existing `<style>` block:

```css
.resume-item {
  display: flex; justify-content: space-between; align-items: center;
  background: #111827; border: 1px solid #334155; border-radius: 8px;
  padding: 8px 12px; cursor: pointer;
}
.resume-item:hover { border-color: #2563eb; }
.resume-item .ri-date { font-weight: bold; color:#e2e8f0; }
.resume-item .ri-meta { font-size: 11px; color:#94a3b8; }
```

- [ ] **Step 3: Add `loadResumeAudits()` JavaScript function**

Add after `loadSites()` (line 357):

```javascript
async function loadResumeAudits() {
  const siteId = document.getElementById("siteSelect").value;
  const panel = document.getElementById("resumePanel");
  const list = document.getElementById("resumeList");
  if (!siteId) { panel.style.display = "none"; return; }

  const res = await fetch(`${API}/audits/resume/${encodeURIComponent(siteId)}`);
  const batches = await res.json();

  if (!batches || batches.length === 0) {
    panel.style.display = "none";
    return;
  }

  list.innerHTML = "";
  batches.forEach(b => {
    const item = document.createElement("div");
    item.className = "resume-item";
    item.innerHTML = `
      <div>
        <div class="ri-date">${escHtml(b.audit_date)}</div>
        <div class="ri-meta">${b.entry_count || 0} devices | ${escHtml(b.audit_batch_id || "").substring(0, 8)}…</div>
      </div>
      <button onclick="resumeAudit('${b.audit_batch_id}')" style="background:#16a34a;padding:6px 14px;">Resume</button>
    `;
    list.appendChild(item);
  });
  panel.style.display = "block";
}
```

- [ ] **Step 4: Add `resumeAudit()` JavaScript function**

Add after `loadResumeAudits()`:

```javascript
async function resumeAudit(id) {
  batchId = id;
  const siteName = selectedSiteName();
  document.getElementById("auditStatus").textContent = `Resumed audit: ${siteName} | Batch: ${batchId}`;
  document.getElementById("resumePanel").style.display = "none";
  await loadAudit();
}
```

- [ ] **Step 5: Wire site select `onchange` to call `loadResumeAudits`**

Change the site select element (line 202) to:

```html
<select id="siteSelect" onchange="loadResumeAudits()"></select>
```

---

### Task 7: UI — device-audit.html — Status badge and Finalize/Re-open buttons

**Files:**
- Modify: `device-audit.html`

- [ ] **Step 1: Add status badge and action buttons HTML to Current Audit card**

Replace the `.actions` div in the "Current Audit" card (lines 217-220) with:

```html
<div class="actions" style="margin-bottom:8px;">
  <p id="auditStatus" class="status-line" style="margin:0;">No audit started.</p>
  <span id="statusBadge" style="display:none; padding:4px 10px; border-radius:6px; font-size:12px; font-weight:bold;"></span>
  <button id="finalizeBtn" onclick="finalizeAudit()" style="display:none; background:#f59e0b;">Finalize Audit</button>
  <button id="reopenBtn" onclick="reopenAudit()" style="display:none; background:#6366f1;">Re-open Audit</button>
  <button onclick="saveAllRows()" style="background:#16a34a;">Save All Rows</button>
</div>
```

- [ ] **Step 2: Add CSS for status badge**

Add to `<style>`:

```css
.badge-in_progress { background: #1e3a5f; color: #93c5fd; border: 1px solid #2563eb; }
.badge-finalized { background: #1a2e1a; color: #86efac; border: 1px solid #16a34a; }
```

- [ ] **Step 3: Add `updateStatusUI()` JavaScript function**

Add after `resumeAudit()`:

```javascript
async function updateStatusUI() {
  const badge = document.getElementById("statusBadge");
  const finalizeBtn = document.getElementById("finalizeBtn");
  const reopenBtn = document.getElementById("reopenBtn");
  if (!batchId) { badge.style.display = "none"; finalizeBtn.style.display = "none"; reopenBtn.style.display = "none"; return; }

  const res = await fetch(`${API}/audit-batch/${batchId}`);
  if (!res.ok) return;
  const batch = await res.json();
  const status = batch.status || "in_progress";

  badge.style.display = "inline-block";
  badge.className = `badge-${status}`;
  badge.textContent = status === "in_progress" ? "In Progress" : "Finalized";

  finalizeBtn.style.display = status === "in_progress" ? "inline-block" : "none";
  reopenBtn.style.display = status === "finalized" ? "inline-block" : "none";
}
```

- [ ] **Step 4: Add `finalizeAudit()` and `reopenAudit()` JavaScript functions**

Add after `updateStatusUI()`:

```javascript
async function finalizeAudit() {
  if (!confirm("Finalize this audit? It will be marked as complete.")) return;
  const res = await fetch(`${API}/audits/${batchId}/finalize`, { method: "POST" });
  if (!res.ok) { alert("Finalize failed."); return; }
  await updateStatusUI();
}

async function reopenAudit() {
  if (!confirm("Re-open this audit? It will be marked as in progress again.")) return;
  const res = await fetch(`${API}/audits/${batchId}/reopen`, { method: "POST" });
  if (!res.ok) { alert("Re-open failed."); return; }
  await updateStatusUI();
}
```

- [ ] **Step 5: Call `updateStatusUI()` after `loadAudit()` completes**

In the `loadAudit()` function, add `await updateStatusUI();` at the end of the function. The function is already async. Add after line 487 (after the `tbody.appendChild(row);` loop ends):

```javascript
  await updateStatusUI();
```

- [ ] **Step 6: Also call `updateStatusUI()` in `resumeAudit()`**

Add `await updateStatusUI();` after `await loadAudit();` in `resumeAudit()`.

---

### Task 8: UI — audit-reports.html — Status column and Finalize/Re-open buttons

**Files:**
- Modify: `audit-reports.html`

- [ ] **Step 1: Add Status column header**

The table header currently has columns at lines 182-194. Add a "Batch Status" column header before "Stored". Change line 186 from:

```html
          <th>View</th>
          <th>Stored</th>
```

to:

```html
          <th>View</th>
          <th>Batch Status</th>
          <th>Stored</th>
```

- [ ] **Step 2: Add CSS for status badges**

Add to `<style>` block:

```css
.badge-in_progress { background: #1e3a5f; color: #93c5fd; border: 1px solid #2563eb; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; }
.badge-finalized { background: #1a2e1a; color: #86efac; border: 1px solid #16a34a; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; }
.action-btn-finalize { background: #f59e0b; border: none; font-weight: bold; cursor: pointer; padding: 4px 10px; border-radius: 6px; font-size: 11px; }
.action-btn-reopen { background: #6366f1; border: none; font-weight: bold; cursor: pointer; padding: 4px 10px; border-radius: 6px; font-size: 11px; }
.action-btn-finalize:hover { background: #d97706; }
.action-btn-reopen:hover { background: #4f46e5; }
```

- [ ] **Step 3: Add status cell and action buttons to batch row**

In `loadBatches()`, the row HTML is at lines 311-353. Add a status cell after the View cell and before the Stored cell. Replace lines 330-338:

Current:
```javascript
      <td>
        <button onclick="viewReport('${batch.audit_batch_id}')">
          View
        </button>
      </td>

      <td class="${batch.report_generated ? "generated-yes" : "generated-no"}">
        ${batch.report_generated ? "YES" : "NO"}
      </td>
```

Replace with:
```javascript
      <td>
        <button onclick="viewReport('${batch.audit_batch_id}')">
          View
        </button>
      </td>

      <td>
        <span class="badge-${batch.status || "in_progress"}">${(batch.status || "in_progress") === "in_progress" ? "In Progress" : "Finalized"}</span>
      </td>

      <td class="${batch.report_generated ? "generated-yes" : "generated-no"}">
        ${batch.report_generated ? "YES" : "NO"}
      </td>
```

- [ ] **Step 4: Add Finalize/Re-open action buttons after the existing action buttons**

In the action cells area (around lines 311-328), add a new column for batch status actions. Current first action cell has "Generate" button. Add a Finalize/Re-open button there. Insert after the "Generate" button (line 314):

```javascript
      <td>
        <button onclick="storeReport('${batch.audit_batch_id}')">
          Generate
        </button>
        ${batch.status === "in_progress"
          ? `<button class="action-btn-finalize" onclick="finalizeBatch('${batch.audit_batch_id}')">Finalize</button>`
          : `<button class="action-btn-reopen" onclick="reopenBatch('${batch.audit_batch_id}')">Re-open</button>`}
      </td>
```

But wait, the current first column is `<td><button onclick="storeReport(...)">Generate</button></td>`. We need to combine them. Let me restructure.

Replace the entire first td (lines 311-316):

```javascript
      <td style="display:flex;flex-direction:column;gap:4px;border:1px solid #334155;padding:6px;">
        <button onclick="storeReport('${batch.audit_batch_id}')" style="font-size:11px;padding:4px 8px;">
          Generate
        </button>
        ${batch.status === "in_progress"
          ? `<button class="action-btn-finalize" onclick="finalizeBatch('${batch.audit_batch_id}')">Finalize</button>`
          : `<button class="action-btn-reopen" onclick="reopenBatch('${batch.audit_batch_id}')">Re-open</button>`}
      </td>
```

Actually, looking at the original HTML more carefully, each cell is in its own `<td>`. Let me not change the layout too much. Instead, I'll add the finalize/reopen button in the first action td alongside the Generate button — inside the same td, just a line break or next to it.

Replace lines 311-316:
```javascript
      <td>
        <div style="display:flex;flex-wrap:wrap;gap:4px;">
          <button onclick="storeReport('${batch.audit_batch_id}')" style="font-size:11px;padding:4px 8px;">
            Generate
          </button>
          ${batch.status === "in_progress"
            ? `<button class="action-btn-finalize" onclick="finalizeBatch('${batch.audit_batch_id}')">Finalize</button>`
            : `<button class="action-btn-reopen" onclick="reopenBatch('${batch.audit_batch_id}')">Re-open</button>`}
        </div>
      </td>
```

- [ ] **Step 5: Add `finalizeBatch()` and `reopenBatch()` JavaScript functions**

Add after `uploadSharePoint()` (around line 422):

```javascript
async function finalizeBatch(batchId) {
  if (!confirm("Finalize this audit batch?")) return;
  const res = await fetch(`${API}/audits/${batchId}/finalize`, { method: "POST" });
  if (!res.ok) { alert("Finalize failed."); return; }
  loadBatches();
}

async function reopenBatch(batchId) {
  if (!confirm("Re-open this audit batch?")) return;
  const res = await fetch(`${API}/audits/${batchId}/reopen`, { method: "POST" });
  if (!res.ok) { alert("Re-open failed."); return; }
  loadBatches();
}
```

---

### Task 9: Verify — Restart the API server and test

**Files:**
- N/A (verification step)

- [ ] **Step 1: Restart the API server**

```bash
# Kill existing processes on the audit API port
pkill -f "device_audit_api.py" || true
# Restart
cd /home/aiagent/mission-control-ui && nohup python3 device_audit_api.py > /tmp/audit_api.log 2>&1 &
```

- [ ] **Step 2: Test resume endpoint**

```bash
# Get a site ID first
SITE_ID=$(curl -s http://127.0.0.1:8096/sites | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['site_id'] if d else '')")
echo "Site: $SITE_ID"
# Test resume list (should be empty initially, then show audits after creating one)
curl -s "http://127.0.0.1:8096/audits/resume/$SITE_ID" | python3 -m json.tool
```

- [ ] **Step 3: Test finalize endpoint**

```bash
# Get a batch ID
BATCH_ID=$(curl -s "http://127.0.0.1:8096/audit-batches?site_id=$SITE_ID" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['audit_batch_id'] if d else '')")
echo "Batch: $BATCH_ID"
# Finalize
curl -s -X POST "http://127.0.0.1:8096/audits/$BATCH_ID/finalize" | python3 -m json.tool
```

- [ ] **Step 4: Test reopen endpoint**

```bash
curl -s -X POST "http://127.0.0.1:8096/audits/$BATCH_ID/reopen" | python3 -m json.tool
```
