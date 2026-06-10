"""
Mission Control — Executive PDF Report Generator
Uses WeasyPrint to produce branded, professional audit compliance reports.
"""
import os
import re
from datetime import datetime, date
from typing import Any, Dict, List, Optional
from html import escape

from weasyprint import HTML


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(value) -> str:
    """HTML-escape a value, returning 'N/A' for blanks."""
    if value is None or value == "":
        return "N/A"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return escape(str(value))


def format_au_date(value) -> str:
    if not value:
        return "N/A"
    text = str(value).strip()
    if not text:
        return "N/A"
    try:
        clean = text.replace("Z", "+00:00")
        if "T" in clean or " " in clean:
            return datetime.fromisoformat(clean).strftime("%d/%m/%Y")
        return datetime.fromisoformat(clean).date().strftime("%d/%m/%Y")
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(text[:10], fmt).strftime("%d/%m/%Y")
        except Exception:
            continue
    return _esc(value)


def fmt(value) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    au = format_au_date(value)
    if au != str(value) and re.match(r"^\d{4}-\d{2}-\d{2}", str(value).strip()):
        return au
    return _esc(value)


def room_name(row: dict) -> str:
    return (
        row.get("assigned_user_room")
        or row.get("assigned_room")
        or row.get("assigned_user")
        or "Unassigned"
    )


def device_label(row: dict) -> str:
    return row.get("brand_model") or row.get("device_name") or "N/A"


def photo_count(row: dict) -> int:
    try:
        return int(row.get("photos_count") or row.get("total_photos") or 0)
    except Exception:
        return 0


def is_missing(row: dict) -> bool:
    return row.get("device_present") is False


def _normalize(v) -> str:
    return str(v).strip() if v else ""


def has_credential_issue(row: dict) -> bool:
    text = " ".join([_normalize(row.get("notes")), _normalize(row.get("breach_notes")), _normalize(row.get("recommended_action"))]).lower()
    return (
        row.get("password_issue") is True
        or row.get("weak_pin_detected") is True
        or row.get("security_breach") is True
        or any(k in text for k in ("password", "pin", "123456", "sticker", "credential"))
    )


def has_hardware_issue(row: dict) -> bool:
    text = " ".join([_normalize(row.get("notes")), _normalize(row.get("breach_notes")), _normalize(row.get("recommended_action"))]).lower()
    return any(k in text for k in ("broken", "battery", "hinge", "keyboard", "screen", "touch", "protector", "fault", "repair", "flat", "missing key"))


def is_photo_action(row: dict, retention_days: int = 31, photo_threshold: int = 1000) -> bool:
    pc = photo_count(row)
    pd = row.get("photos_date")
    if pd:
        try:
            clean = str(pd).strip().replace("Z", "+00:00")
            if "T" in clean or " " in clean:
                dt = datetime.fromisoformat(clean)
            else:
                dt = datetime.fromisoformat(clean)
            age = (datetime.now(dt.tzinfo) - dt).days if dt.tzinfo else (datetime.now() - dt).days
            if age > retention_days:
                return True
        except Exception:
            pass
    return pc > photo_threshold


def status_pill(status: str) -> str:
    cls = {"critical": "pill-critical", "warning": "pill-warning", "ok": "pill-ok", "ignored": "pill-ignored"}.get(status, "")
    label = _esc(status.upper()) if status else "N/A"
    return f'<span class="pill {cls}">{label}</span>'


def score_class(score: int) -> str:
    if score >= 85:
        return "score-green"
    if score >= 60:
        return "score-amber"
    return "score-red"


def risk_class(risk: str) -> str:
    if risk == "High Risk":
        return "risk-high"
    if risk == "Needs Attention":
        return "risk-amber"
    return "risk-green"


# ---------------------------------------------------------------------------
# CSS — WeasyPrint compatible (no flexbox, uses tables for layout)
# ---------------------------------------------------------------------------

CSS = """
@page {
    size: A4 landscape;
    margin: 10mm 10mm 14mm 10mm;
    @bottom-left {
        content: "Mission Control — Confidential";
        font-size: 7.5pt;
        color: #94a3b8;
        font-family: Arial, Helvetica, sans-serif;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 7.5pt;
        color: #94a3b8;
        font-family: Arial, Helvetica, sans-serif;
    }
}

@page cover {
    margin: 0;
    @bottom-left { content: none; }
    @bottom-right { content: none; }
}

body {
    font-family: Arial, Helvetica, sans-serif;
    font-size: 7.5pt;
    color: #1e293b;
    line-height: 1.35;
}

/* --- Cover page --- */
.cover {
    page: cover;
    page-break-after: always;
    width: 100%;
    height: 100%;
    position: relative;
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: #f8fafc;
}
.cover-inner {
    padding: 60mm 25mm 30mm 25mm;
}
.cover h1 {
    font-size: 32pt;
    margin: 0 0 6px 0;
    border: none;
    color: #f8fafc;
    letter-spacing: -0.5px;
}
.cover .cover-subtitle {
    font-size: 14pt;
    color: #93c5fd;
    margin: 0 0 30px 0;
    font-weight: 400;
}
.cover .cover-meta {
    font-size: 11pt;
    color: #cbd5e1;
    line-height: 2;
    margin-top: 24px;
}
.cover .cover-meta strong {
    color: #f8fafc;
}
.cover-badge {
    display: inline-block;
    margin-top: 30px;
    padding: 10px 24px;
    border-radius: 8px;
    font-size: 14pt;
    font-weight: 700;
}
.cover-badge.score-green { background: #166534; color: #dcfce7; }
.cover-badge.score-amber { background: #92400e; color: #fef3c7; }
.cover-badge.score-red   { background: #991b1b; color: #fecaca; }

.cover-footer {
    position: absolute;
    bottom: 20mm;
    left: 25mm;
    right: 25mm;
    border-top: 1px solid #334155;
    padding-top: 8px;
    font-size: 8pt;
    color: #64748b;
}

/* --- Headings --- */
h1 {
    font-size: 16pt;
    color: #0f172a;
    margin: 0 0 4px 0;
    padding-bottom: 5px;
    border-bottom: 3px solid #2563eb;
}
h2 {
    font-size: 11pt;
    color: #1e40af;
    margin: 14px 0 6px 0;
    padding-bottom: 3px;
    border-bottom: 1px solid #cbd5e1;
}
h3 {
    font-size: 9pt;
    color: #334155;
    margin: 10px 0 4px 0;
}
.section-intro {
    color: #475569;
    font-size: 7pt;
    margin: 0 0 6px 0;
}

/* --- Score card (table based for WeasyPrint) --- */
.score-card-table {
    border-collapse: separate;
    border-spacing: 6px 0;
    margin: 6px 0 10px 0;
}
.score-card-table td {
    text-align: center;
    vertical-align: top;
    padding: 0;
    border: none;
}
.kpi-box {
    border-radius: 6px;
    padding: 6px 12px;
    min-width: 80px;
    text-align: center;
}
.kpi-box .kpi-label {
    font-size: 7pt;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #64748b;
    margin-bottom: 2px;
}
.kpi-box .kpi-value {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
}
.kpi-light   { background: #f1f5f9; border: 1px solid #e2e8f0; }
.kpi-red     { background: #fef2f2; border: 1px solid #fecaca; }
.kpi-red .kpi-value { color: #dc2626; }
.kpi-amber   { background: #fffbeb; border: 1px solid #fde68a; }
.kpi-amber .kpi-value { color: #d97706; }
.kpi-green   { background: #f0fdf4; border: 1px solid #bbf7d0; }
.kpi-green .kpi-value { color: #16a34a; }

/* Score + Risk badges */
.badge-large {
    display: inline-block;
    padding: 5px 14px;
    border-radius: 6px;
    font-size: 14pt;
    font-weight: 700;
    margin-right: 8px;
}
.score-green { background: #dcfce7; color: #166534; border: 2px solid #22c55e; }
.score-amber { background: #fef3c7; color: #92400e; border: 2px solid #f59e0b; }
.score-red   { background: #fecaca; color: #991b1b; border: 2px solid #ef4444; }

.risk-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 6px;
    font-size: 10pt;
    font-weight: 600;
}
.risk-high  { background: #fecaca; color: #991b1b; }
.risk-amber { background: #fef3c7; color: #92400e; }
.risk-green { background: #dcfce7; color: #166534; }

/* --- Tables --- */
table.data {
    width: 100%;
    border-collapse: collapse;
    margin: 4px 0 10px 0;
    font-size: 7pt;
}
table.data th {
    background: #1e293b;
    color: #f8fafc;
    padding: 4px 5px;
    text-align: left;
    font-weight: 600;
    font-size: 6.5pt;
    text-transform: uppercase;
    letter-spacing: 0.2px;
}
table.data td {
    padding: 3px 5px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
    line-height: 1.25;
}
table.data tr:nth-child(even) td { background: #f8fafc; }
table.data tr.row-critical td { border-left: 3px solid #ef4444; }
table.data tr.row-warning td  { border-left: 3px solid #f59e0b; }
table.data tr.row-missing td  { background: #fef2f2; }

/* Status pills */
.pill {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 4px;
    font-size: 7pt;
    font-weight: 700;
    text-transform: uppercase;
    white-space: nowrap;
}
.pill-critical { background: #fecaca; color: #991b1b; }
.pill-warning  { background: #fef3c7; color: #92400e; }
.pill-ok       { background: #dcfce7; color: #166534; }
.pill-ignored  { background: #e2e8f0; color: #64748b; }

/* Findings */
.finding {
    margin: 4px 0;
    padding: 6px 10px;
    border-left: 3px solid #3b82f6;
    background: #f1f5f9;
    font-size: 7.5pt;
}
.finding-critical { border-left-color: #ef4444; background: #fef2f2; }
.finding-warning  { border-left-color: #f59e0b; background: #fffbeb; }
.finding-ok       { border-left-color: #22c55e; background: #f0fdf4; }

/* Recommendations */
.rec-item {
    padding: 4px 8px;
    margin: 2px 0;
    background: #eff6ff;
    border-left: 3px solid #3b82f6;
    font-size: 7.5pt;
}
.rec-number {
    font-weight: 700;
    color: #1e40af;
    margin-right: 6px;
}

/* Table of contents */
.toc {
    margin: 12px 0 0 0;
    padding: 0;
    list-style: none;
}
.toc li {
    padding: 2px 0;
    font-size: 8pt;
    border-bottom: 1px dotted #cbd5e1;
}
.toc li a {
    color: #1e40af;
    text-decoration: none;
}

.page-break { page-break-before: always; }
.avoid-break { page-break-inside: avoid; }

/* Device type breakdown mini table */
table.mini {
    border-collapse: collapse;
    margin: 4px 0 8px 0;
    font-size: 7.5pt;
}
table.mini th {
    background: #f1f5f9;
    color: #334155;
    padding: 4px 12px;
    text-align: left;
    font-weight: 600;
    border-bottom: 2px solid #cbd5e1;
}
table.mini td {
    padding: 3px 12px;
    border-bottom: 1px solid #e2e8f0;
}
"""


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def build_executive_pdf_html(report: Dict[str, Any], score: int, risk_label: str) -> str:
    rows = report.get("rows", [])
    summary = report.get("summary", {})
    site_name = fmt(report.get("site_name"))
    audit_date = format_au_date(report.get("audit_date"))
    generated_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    batch_id = _esc(report.get("audit_batch_id", ""))

    site_config = report.get("site_config") or {}
    retention_days  = int(site_config.get("photo_retention_days")  or 31)
    photo_threshold = int(site_config.get("photo_count_threshold") or 1000)
    audit_frequency = int(site_config.get("audit_frequency_days")  or 90)
    _pol_keys = [
        "consent_forms_current","photo_policy_documented","staff_training_current",
        "encryption_enforced","access_controls_documented","data_retention_policy",
        "incident_response_plan","privacy_impact_assessment","third_party_data_agreement",
    ]
    policy_confirmed = sum(1 for k in _pol_keys if site_config.get(k) is True)
    policy_total     = len(_pol_keys)

    active_rows = [r for r in rows if r.get("status") != "ignored"]
    critical_rows = [r for r in active_rows if r.get("status") == "critical"]
    warning_rows = [r for r in active_rows if r.get("status") == "warning"]
    ok_rows = [r for r in active_rows if r.get("status") == "ok"]
    missing_rows = [r for r in active_rows if is_missing(r)]
    credential_rows = [r for r in active_rows if has_credential_issue(r)]
    hardware_rows = [r for r in active_rows if has_hardware_issue(r)]
    photo_action_rows = [r for r in active_rows if is_photo_action(r, retention_days=retention_days, photo_threshold=photo_threshold)]

    # Device type counts
    dtype_counts: Dict[str, int] = {}
    for r in active_rows:
        dt = fmt(r.get("device_type")).title()
        dtype_counts[dt] = dtype_counts.get(dt, 0) + 1

    # Build critical actions
    actions = []
    for r in active_rows:
        room = room_name(r)
        serial = r.get("serial_number", "")
        model = device_label(r)
        dtype = r.get("device_type") or "Device"
        issue_text = _normalize(r.get("breach_notes")) or _normalize(r.get("recommended_action")) or _normalize(r.get("notes"))

        if is_missing(r):
            actions.append(("Missing Asset", room, serial, f"{dtype} {model} not sighted", "Locate / verify / disable access"))
        if has_credential_issue(r):
            actions.append(("Credential Security", room, serial, issue_text or "Credential/PIN concern", "Reset credentials; apply unique device/room credentials"))
        if has_hardware_issue(r):
            actions.append(("Hardware", room, serial, issue_text or "Hardware issue recorded", "Repair, replace or risk-accept"))
        if is_photo_action(r, retention_days=retention_days, photo_threshold=photo_threshold):
            actions.append(("Photo Retention", room, serial, f"{photo_count(r)} photos — {format_au_date(r.get('photos_date'))}", "Reduce to under 30 days"))

    sc = score_class(score)
    rc = risk_class(risk_label)

    # ---- Cover page ----
    cover = f"""
    <div class="cover">
        <div class="cover-inner">
            <h1>Site Audit Report</h1>
            <div class="cover-subtitle">Digital Device, Photo Retention &amp; Cloud Sync Compliance Audit</div>

            <div class="cover-meta">
                <strong>Site:</strong> {site_name}<br>
                <strong>Audit Date:</strong> {audit_date}<br>
                <strong>Report Generated:</strong> {generated_at}<br>
                <strong>Overall Status:</strong> {"Compliant" if risk_label == "On Track" else "Not Compliant"}<br>
                <strong>Batch ID:</strong> {batch_id}<br>
                <strong>Photo Retention Policy:</strong> {retention_days} days&nbsp;|&nbsp;Photo Threshold: {photo_threshold} photos<br>
                <strong>Audit Frequency:</strong> Every {audit_frequency} days&nbsp;|&nbsp;<strong>Policy Checklist:</strong> {policy_confirmed}/{policy_total} confirmed
            </div>

            <div class="cover-badge {sc}">{score} / 100</div>
            <span class="risk-badge {rc}" style="margin-left:12px;font-size:12pt;">{_esc(risk_label)}</span>
        </div>
        <div class="cover-footer">
            This report is confidential and intended for internal use only.
            Generated by Mission Control Audit Platform.
        </div>
    </div>
    """

    # ---- Table of contents ----
    toc_items = [
        ("Executive Summary", "exec-summary"),
        ("Key Findings", "key-findings"),
        ("Recommendations", "recommendations"),
        ("Missing Devices — Immediate Action", "missing-devices"),
        ("Critical Incidents &amp; Actions", "critical-actions"),
        ("Detailed Audit by Room / User", "room-detail"),
        ("Photo Retention Review", "photo-review"),
        ("Policy Compliance Checklist", "policy-compliance"),
    ]

    toc_html = '<ul class="toc">' + "".join(
        f'<li><a href="#{anchor}">{label}</a></li>' for label, anchor in toc_items
    ) + "</ul>"

    # ---- Executive summary ----
    summary_html = f"""
    <h1 id="exec-summary">Executive Summary</h1>

    <table class="score-card-table"><tr>
        <td><div class="kpi-box kpi-light">
            <div class="kpi-label">Compliance Score</div>
            <div class="kpi-value"><span class="badge-large {sc}">{score}/100</span></div>
        </div></td>
        <td><div class="kpi-box kpi-light">
            <div class="kpi-label">Risk Rating</div>
            <div class="kpi-value"><span class="risk-badge {rc}">{_esc(risk_label)}</span></div>
        </div></td>
        <td><div class="kpi-box kpi-light">
            <div class="kpi-label">Overall Status</div>
            <div class="kpi-value">{"Compliant" if risk_label == "On Track" else "Not Compliant"}</div>
        </div></td>
    </tr></table>

    <table class="score-card-table"><tr>
        <td><div class="kpi-box kpi-light"><div class="kpi-label">Total Devices</div><div class="kpi-value">{summary.get("total_devices", 0)}</div></div></td>
        <td><div class="kpi-box kpi-red"><div class="kpi-label">Critical</div><div class="kpi-value">{summary.get("critical", 0)}</div></div></td>
        <td><div class="kpi-box kpi-amber"><div class="kpi-label">Warnings</div><div class="kpi-value">{summary.get("warnings", 0)}</div></div></td>
        <td><div class="kpi-box kpi-green"><div class="kpi-label">Compliant</div><div class="kpi-value">{summary.get("ok", 0)}</div></div></td>
        <td><div class="kpi-box kpi-red"><div class="kpi-label">Missing</div><div class="kpi-value">{summary.get("missing", 0)}</div></div></td>
        <td><div class="kpi-box kpi-light"><div class="kpi-label">Photo Breaches</div><div class="kpi-value">{summary.get("photo_retention_breaches", 0)}</div></div></td>
        <td><div class="kpi-box kpi-light"><div class="kpi-label">Security Issues</div><div class="kpi-value">{summary.get("security_issues", 0)}</div></div></td>
        <td><div class="kpi-box {"kpi-green" if policy_confirmed == policy_total else "kpi-amber"}"><div class="kpi-label">Policy Checklist</div><div class="kpi-value">{policy_confirmed}/{policy_total}</div></div></td>
    </tr></table>

    <h3>Device Breakdown</h3>
    <table class="mini">
        <tr><th>Device Type</th><th>Count</th></tr>
        {"".join(f"<tr><td>{_esc(dt)}</td><td>{c}</td></tr>" for dt, c in sorted(dtype_counts.items()))}
    </table>
    """

    # ---- Key findings ----
    findings_parts = []
    findings_parts.append(f'<div class="finding">{len(active_rows)} total device records audited in this batch.</div>')
    if missing_rows:
        findings_parts.append(f'<div class="finding finding-critical">{len(missing_rows)} device(s) <strong>not sighted</strong> during audit — escalated to Missing Assets Register.</div>')
    if credential_rows:
        findings_parts.append(f'<div class="finding finding-critical">{len(credential_rows)} device(s) with <strong>credential or security concerns</strong> requiring remediation.</div>')
    if photo_action_rows:
        findings_parts.append(f'<div class="finding finding-warning">{len(photo_action_rows)} device(s) with <strong>photo retention</strong> older than {retention_days} days or exceeding {photo_threshold} photos.</div>')
    if hardware_rows:
        findings_parts.append(f'<div class="finding finding-warning">{len(hardware_rows)} device(s) with <strong>hardware issues</strong> requiring repair or replacement.</div>')
    if not critical_rows and not warning_rows and not missing_rows:
        findings_parts.append('<div class="finding finding-ok">No critical or warning findings. All devices compliant.</div>')

    findings_html = f'<h2 id="key-findings">Key Findings</h2>' + "\n".join(findings_parts)

    # ---- Recommendations ----
    recommendations = list(report.get("recommendations", []))
    rec_set = set(recommendations)
    if hardware_rows and "Repair, replace or risk accept faulty devices that affect secure and reliable operation." not in rec_set:
        recommendations.append("Repair, replace or risk accept faulty devices that affect secure and reliable operation.")
    if credential_rows and "Remove visible/shared credentials and replace standard PINs with unique room/device credentials." not in rec_set:
        recommendations.append("Remove visible/shared credentials and replace standard PINs with unique room/device credentials.")

    rec_html = f'<h2 id="recommendations">Recommendations</h2>'
    for i, r in enumerate(recommendations, 1):
        rec_html += f'<div class="rec-item"><span class="rec-number">{i}.</span> {_esc(r)}</div>'

    # ---- Missing devices ----
    missing_html = """
    <div class="page-break"></div>
    <h2 id="missing-devices">Missing Devices — Immediate Action Required</h2>
    <p class="section-intro">The following devices were not sighted during the audit. These require physical verification,
    access review and, where child data could be present, privacy/security escalation.</p>
    """
    if missing_rows:
        missing_html += """<table class="data">
        <tr><th>Device Type</th><th>Room / User</th><th>Brand / Model</th><th>Serial</th><th>Risk Note</th><th>Required Action</th></tr>
        """
        for r in missing_rows:
            missing_html += f'<tr class="row-missing"><td>{fmt(r.get("device_type"))}</td><td>{_esc(room_name(r))}</td><td>{_esc(device_label(r))}</td><td>{fmt(r.get("serial_number"))}</td><td>Potential data or operational exposure</td><td>Locate / verify / disable access</td></tr>'
        missing_html += "</table>"
    else:
        missing_html += '<div class="finding finding-ok">No missing devices recorded. All devices were sighted during audit.</div>'

    # ---- Critical incidents & actions ----
    actions_html = """
    <h2 id="critical-actions">Critical Incidents &amp; Immediate Actions</h2>
    <p class="section-intro">Summary of all incidents requiring immediate remediation, grouped by type.</p>
    """
    if actions:
        actions_html += """<table class="data">
        <tr><th>Incident Type</th><th>Room / User</th><th>Serial</th><th>Issue</th><th>Required Action</th></tr>
        """
        for itype, room, serial, issue, action in actions:
            row_cls = "row-critical" if itype in ("Missing Asset", "Credential Security") else "row-warning"
            actions_html += f'<tr class="{row_cls}"><td><strong>{_esc(itype)}</strong></td><td>{_esc(room)}</td><td>{fmt(serial)}</td><td>{_esc(issue)}</td><td>{_esc(action)}</td></tr>'
        actions_html += "</table>"
    else:
        actions_html += '<div class="finding finding-ok">No critical incidents or immediate actions required.</div>'

    # ---- Room detail tables ----
    grouped: Dict[str, list] = {}
    for r in sorted(active_rows, key=lambda x: (room_name(x).lower(), device_label(x).lower())):
        grouped.setdefault(room_name(r), []).append(r)

    rooms_html = f'<div class="page-break"></div><h2 id="room-detail">Detailed Audit by Room / User</h2>'
    rooms_html += f'<p class="section-intro">Complete device-level detail for each room or assigned user, with OS, sync, photo and issue data.</p>'

    for room, room_rows in grouped.items():
        rooms_html += f'<div class="avoid-break"><h3>{_esc(room)}</h3>'
        rooms_html += """<table class="data">
        <tr><th>Type</th><th>Brand / Model</th><th>Serial</th><th>OS / Updates</th><th>Sync (OneDrive / Camera / iCloud)</th><th>Photos</th><th>Issues / Notes</th><th>Status</th></tr>"""
        for r in room_rows:
            st = r.get("status", "")
            row_cls = f"row-{st}" if st in ("critical", "warning") else ""
            if is_missing(r):
                row_cls = "row-missing"

            photos = f'{photo_count(r)} photos'
            pd = format_au_date(r.get("photos_date"))
            if pd != "N/A":
                photos += f" ({pd})"

            os_parts = []
            win_os = r.get("windows_os") or r.get("os_version")
            if win_os:
                os_parts.append(f"OS: {fmt(win_os)}")
            if r.get("windows_updates"):
                os_parts.append(f"Updates: {fmt(r.get('windows_updates'))}")
            if r.get("security_check"):
                os_parts.append(f"Security: {fmt(r.get('security_check'))}")
            ios = r.get("ios_version") or r.get("update_status")
            if ios:
                os_parts.append(f"iOS: {fmt(ios)}")
            os_info = "; ".join(os_parts) if os_parts else "N/A"

            sync_parts = []
            if r.get("onedrive_sync_on") is not None:
                sync_parts.append(f"OneDrive: {fmt(r.get('onedrive_sync_on'))}")
            if r.get("onedrive_status"):
                sync_parts.append(f"Status: {fmt(r.get('onedrive_status'))}")
            if r.get("camera_sync_off") is not None:
                sync_parts.append(f"Camera off: {fmt(r.get('camera_sync_off'))}")
            if r.get("icloud_sync_off") is not None:
                sync_parts.append(f"iCloud off: {fmt(r.get('icloud_sync_off'))}")
            sync_info = "; ".join(sync_parts) if sync_parts else "N/A"

            issue_parts = []
            breach = _normalize(r.get("breach_notes"))
            rec_action = _normalize(r.get("recommended_action"))
            notes = _normalize(r.get("notes"))
            if breach:
                issue_parts.append(breach)
            if rec_action:
                issue_parts.append(rec_action)
            if notes and notes.lower() != breach.lower():
                issue_parts.append(notes)
            issues = "; ".join(issue_parts) if issue_parts else "N/A"

            rooms_html += f'<tr class="{row_cls}"><td>{fmt(r.get("device_type"))}</td><td>{_esc(device_label(r))}</td><td>{fmt(r.get("serial_number"))}</td><td>{_esc(os_info)}</td><td>{_esc(sync_info)}</td><td>{photos}</td><td>{_esc(issues)}</td><td>{status_pill(st)}</td></tr>'
        rooms_html += "</table></div>"

    # ---- Photo retention review ----
    photo_html = f"""
    <div class="page-break"></div>
    <h2 id="photo-review">Photo Retention Review</h2>
    <p class="section-intro">Devices with photo counts exceeding {photo_threshold} or photo retention older than {retention_days} days. These require photo reduction to comply with retention policy.</p>
    """
    if photo_action_rows:
        photo_html += """<table class="data">
        <tr><th>Room / User</th><th>Device</th><th>Serial</th><th>Photo Count</th><th>Photo Date</th><th>OneDrive</th><th>Camera Off</th><th>iCloud Off</th><th>Action</th></tr>
        """
        for r in sorted(photo_action_rows, key=lambda x: photo_count(x), reverse=True):
            photo_html += f'<tr><td>{_esc(room_name(r))}</td><td>{_esc(device_label(r))}</td><td>{fmt(r.get("serial_number"))}</td><td>{photo_count(r)}</td><td>{format_au_date(r.get("photos_date"))}</td><td>{fmt(r.get("onedrive_sync_on"))}</td><td>{fmt(r.get("camera_sync_off"))}</td><td>{fmt(r.get("icloud_sync_off"))}</td><td>Reduce to under 30 days</td></tr>'
        photo_html += "</table>"
    else:
        photo_html += '<div class="finding finding-ok">No photo retention issues recorded. All devices within policy.</div>'

    # ---- Assemble full HTML ----
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>{CSS}</style>
</head>
<body>

{cover}

<h2>Contents</h2>
{toc_html}

{summary_html}

{findings_html}

{rec_html}

{missing_html}

{actions_html}

{rooms_html}

{photo_html}

__POLICY_SECTION__

</body>
</html>"""

    # ---- Policy compliance summary ----
    policy_items = [
        ("consent_forms_current",        "Consent forms current"),
        ("photo_policy_documented",       "Photo policy documented"),
        ("staff_training_current",        "Staff privacy training current"),
        ("encryption_enforced",           "Device encryption enforced"),
        ("access_controls_documented",    "Access controls documented"),
        ("data_retention_policy",         "Data retention policy in place"),
        ("incident_response_plan",        "Incident response plan exists"),
        ("privacy_impact_assessment",     "Privacy impact assessment completed"),
        ("third_party_data_agreement",    "Third-party data agreements in place"),
    ]

    policy_rows_html = ""
    has_policy = any(site_config.get(k) is not None for k, _ in policy_items)
    if has_policy:
        for key, label in policy_items:
            val = site_config.get(key)
            if val is True:
                indicator = '<span style="color:#22c55e;font-weight:bold;">&#10003; Yes</span>'
            elif val is False:
                indicator = '<span style="color:#ef4444;font-weight:bold;">&#10007; No</span>'
            else:
                indicator = '<span style="color:#94a3b8;">Not set</span>'
            policy_rows_html += (
                "<tr>"
                "<td style=\"padding:7px 12px;border-bottom:1px solid #e2e8f0;\">" + label + "</td>"
                "<td style=\"padding:7px 12px;border-bottom:1px solid #e2e8f0;text-align:center;\">" + indicator + "</td>"
                "</tr>"
            )

        _pol_summary_color = "#22c55e" if policy_confirmed == policy_total else "#ef4444"
        _pol_summary_text = "All policies in place" if policy_confirmed == policy_total else str(policy_total - policy_confirmed) + " item(s) require attention"
        _pol_summary_box = (
            "<div style=\"background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:10pt;\">"
            "<strong>Policy Score:</strong> " + str(policy_confirmed) + " of " + str(policy_total) + " confirmed"
            " \u2014 <span style=\"color:" + _pol_summary_color + ";font-weight:bold;\">" + _pol_summary_text + "</span>"
            "&nbsp;&nbsp;|&nbsp;&nbsp;<strong>Photo Retention:</strong> " + str(retention_days) + " days"
            "&nbsp;&nbsp;|&nbsp;&nbsp;<strong>Photo Threshold:</strong> " + str(photo_threshold) + " photos"
            "&nbsp;&nbsp;|&nbsp;&nbsp;<strong>Audit Frequency:</strong> Every " + str(audit_frequency) + " days"
            "</div>"
        )
        policy_html = (
            "<div class=\"page-break\"></div>"
            "<div class=\"section\" id=\"policy-compliance\">"
            "<h2>Policy Compliance Checklist</h2>"
            "<p class=\"section-intro\">Site-level policy status as configured in Site Onboarding. "
            "Items marked <strong style=\"color:#ef4444;\">No</strong> require attention.</p>"
            + _pol_summary_box +
            "<table style=\"width:100%;border-collapse:collapse;font-size:10pt;\">"
            "<thead><tr style=\"background:#f1f5f9;\">"
            "<th style=\"padding:8px 12px;text-align:left;border-bottom:2px solid #cbd5e1;\">Policy Item</th>"
            "<th style=\"padding:8px 12px;text-align:center;border-bottom:2px solid #cbd5e1;width:120px;\">Status</th>"
            "</tr></thead><tbody>" + policy_rows_html + "</tbody></table></div>"
        )
    else:
        policy_html = ""

    html = html.replace("__POLICY_SECTION__", policy_html)
    return html


def generate_executive_pdf(report: Dict[str, Any], score: int, risk_label: str, output_dir: str) -> tuple:
    """Generate a branded PDF report and return (file_path, filename)."""
    html_content = build_executive_pdf_html(report, score, risk_label)

    site_name = re.sub(r"[^a-zA-Z0-9_\-]+", "-", (report.get("site_name") or "audit-report")).strip("-").lower()
    batch_id = report.get("audit_batch_id", "unknown")
    audit_date = re.sub(r"[^0-9\-]", "", str(report.get("audit_date") or ""))[:10] or "undated"
    filename = f"{site_name}-{audit_date}-executive.pdf"

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    HTML(string=html_content).write_pdf(output_path)

    return output_path, filename
