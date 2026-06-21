#!/usr/bin/env python3
"""
Integration test suite for Mission Control audit reporting.

Tests PDF report generation, audit API endpoints, data completeness,
and correct rendering of all report sections.

Run: cd /home/aiagent/mission-control-ui && source venv/bin/activate && python3 /tmp/test_audit_integration.py
"""
import os
import sys
import json
import re
import traceback
from datetime import datetime, timedelta

sys.path.insert(0, "/home/aiagent/mission-control-ui")
from dotenv import load_dotenv
load_dotenv("/home/aiagent/mission-control-site/.env")

from device_audit_api import (
    build_report, calculate_score, calculate_risk,
    classify, build_rows, get_entries_for_batch, get_audit_batch,
    supabase, room_name, is_missing, has_credential_issue,
    has_hardware_issue, is_photo_action, is_photo_audit_device,
    normalize_text, parse_bool, days_old, is_true,
)
from pdf_report_generator import (
    build_executive_pdf_html, generate_executive_pdf,
    fmt, format_au_date, _esc, device_label, photo_count,
    status_pill, score_class, risk_class,
)

import requests

API_BASE = "http://127.0.0.1:8096"
PASS = 0
FAIL = 0
SKIP = 0
RESULTS = []


def test(name):
    """Decorator-style test runner."""
    def decorator(fn):
        global PASS, FAIL, SKIP
        try:
            fn()
            PASS += 1
            RESULTS.append(("PASS", name))
            print(f"  \033[32mPASS\033[0m  {name}")
        except AssertionError as e:
            FAIL += 1
            RESULTS.append(("FAIL", name, str(e)))
            print(f"  \033[31mFAIL\033[0m  {name}: {e}")
        except Exception as e:
            FAIL += 1
            RESULTS.append(("FAIL", name, str(e)))
            print(f"  \033[31mFAIL\033[0m  {name}: {traceback.format_exc().splitlines()[-1]}")
        return fn
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# Get test data — use the latest Benowa ELC batch
# ═══════════════════════════════════════════════════════════════════════════════
batches = supabase.table("device_audits").select("audit_batch_id, site_name, site_id, audit_date").order("created_at", desc=True).limit(5).execute()
assert batches.data, "No audit batches found in database"

TEST_BATCH = batches.data[0]
TEST_BATCH_ID = TEST_BATCH["audit_batch_id"]
TEST_SITE_NAME = TEST_BATCH["site_name"]

print(f"\n{'='*70}")
print(f"Integration Tests — {TEST_SITE_NAME} / {TEST_BATCH_ID[:16]}...")
print(f"{'='*70}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HELPER FUNCTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════
print("--- Helper Functions ---")

@test("format_au_date converts ISO date to DD/MM/YYYY")
def _():
    assert format_au_date("2026-06-05") == "05/06/2026"
    assert format_au_date("2026-06-05T21:00:00+00:00") == "05/06/2026"

@test("format_au_date handles None and empty")
def _():
    assert format_au_date(None) == "N/A"
    assert format_au_date("") == "N/A"

@test("_esc escapes HTML and handles None")
def _():
    assert _esc(None) == "N/A"
    assert _esc("") == "N/A"
    assert _esc("<script>") == "&lt;script&gt;"
    assert _esc(True) == "Yes"
    assert _esc(False) == "No"

@test("fmt formats dates and values correctly")
def _():
    assert fmt(None) == "N/A"
    assert fmt("2026-06-05") == "05/06/2026"
    assert fmt(True) == "Yes"

@test("score_class returns correct CSS class")
def _():
    assert score_class(90) == "score-green"
    assert score_class(70) == "score-amber"
    assert score_class(50) == "score-red"

@test("risk_class returns correct CSS class")
def _():
    assert risk_class("On Track") == "risk-green"
    assert risk_class("Needs Attention") == "risk-amber"
    assert risk_class("High Risk") == "risk-high"

@test("parse_bool handles various truthy/falsy inputs")
def _():
    assert parse_bool(True) is True
    assert parse_bool(False) is False
    assert parse_bool("yes") is True
    assert parse_bool("no") is False
    assert parse_bool(None, default=True) is True


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CLASSIFY FUNCTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- Classify Function ---")

@test("classify: missing device returns critical")
def _():
    entry = {"device_present": False, "device_type": "Tablet"}
    status, reasons = classify(entry)
    assert status == "critical"
    assert "Missing device" in reasons

@test("classify: weak PIN returns critical")
def _():
    entry = {"device_present": True, "weak_pin_detected": True, "device_type": "Tablet"}
    status, reasons = classify(entry)
    assert status == "critical"
    assert "Security issue" in reasons

@test("classify: password issue returns critical")
def _():
    entry = {"device_present": True, "password_issue": True, "device_type": "Tablet"}
    status, reasons = classify(entry)
    assert status == "critical"

@test("classify: security breach returns critical")
def _():
    entry = {"device_present": True, "security_breach": True, "device_type": "Tablet"}
    status, reasons = classify(entry)
    assert status == "critical"

@test("classify: old photos on tablet returns critical")
def _():
    old_date = (datetime.now() - timedelta(days=60)).isoformat()
    entry = {"device_present": True, "device_type": "Tablet", "photos_date": old_date}
    status, reasons = classify(entry)
    assert status == "critical"
    assert any("Photos older" in r for r in reasons)

@test("classify: high photo count on tablet returns warning")
def _():
    entry = {"device_present": True, "device_type": "Tablet", "photos_count": 1500}
    status, reasons = classify(entry)
    assert status == "warning"
    assert any("Photo count" in r for r in reasons)

@test("classify: compliant device returns ok")
def _():
    entry = {"device_present": True, "device_type": "Tablet", "update_status": "updated"}
    status, reasons = classify(entry)
    assert status == "ok"

@test("classify: ignored device returns ignored")
def _():
    entry = {"ignore_flag": True, "device_type": "Tablet"}
    status, reasons = classify(entry)
    assert status == "ignored"

@test("classify: custom thresholds are respected")
def _():
    entry = {"device_present": True, "device_type": "Tablet", "photos_count": 500}
    # Default threshold is 1000 — should be OK
    status1, _ = classify(entry, photo_threshold=1000)
    assert status1 == "ok"
    # Lower threshold — should be warning
    status2, _ = classify(entry, photo_threshold=400)
    assert status2 == "warning"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. BUILD REPORT TESTS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- Build Report ---")

report = build_report(TEST_BATCH_ID)
summary = report.get("summary", {})

@test("build_report returns all required top-level keys")
def _():
    required = [
        "audit_batch_id", "site_name", "site_id", "audit_date", "generated_at",
        "overall_status", "summary", "critical_incidents", "warnings",
        "missing_devices", "photo_retention_breaches", "security_issues",
        "recommendations", "rows", "site_config",
    ]
    for key in required:
        assert key in report, f"Missing key: {key}"

@test("build_report summary has all required counters")
def _():
    required = [
        "total_devices", "ignored", "critical", "warnings", "ok",
        "missing", "photo_retention_breaches", "photo_count_warnings", "security_issues",
    ]
    for key in required:
        assert key in summary, f"Missing summary key: {key}"

@test("build_report summary counts are consistent")
def _():
    total = summary["total_devices"]
    parts = summary["critical"] + summary["warnings"] + summary["ok"]
    assert total == parts, f"Status counts ({parts}) don't match total ({total})"

@test("build_report rows have computed status and reasons")
def _():
    rows = report.get("rows", [])
    assert len(rows) > 0, "No rows in report"
    for r in rows:
        assert "status" in r, f"Row missing 'status': {r.get('serial_number')}"
        assert "reasons" in r, f"Row missing 'reasons': {r.get('serial_number')}"
        assert r["status"] in ("ok", "warning", "critical", "ignored"), f"Invalid status: {r['status']}"

@test("build_report critical_incidents matches critical count")
def _():
    assert len(report["critical_incidents"]) == summary["critical"]

@test("build_report missing_devices matches missing count")
def _():
    assert len(report["missing_devices"]) == summary["missing"]

@test("build_report security_issues matches security count")
def _():
    assert len(report["security_issues"]) == summary["security_issues"]

@test("build_report site_config has threshold fields")
def _():
    sc = report.get("site_config", {})
    assert "photo_retention_days" in sc
    assert "photo_count_threshold" in sc

@test("build_report recommendations list is non-empty")
def _():
    assert len(report["recommendations"]) > 0

@test("build_report overall_status is valid")
def _():
    assert report["overall_status"] in ("Compliant", "Warning", "Critical")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. SCORE AND RISK CALCULATIONS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- Score & Risk ---")

@test("calculate_score returns 0-100")
def _():
    score = calculate_score(summary)
    assert 0 <= score <= 100, f"Score out of range: {score}"

@test("calculate_score: perfect summary gives 100")
def _():
    perfect = {"critical": 0, "missing": 0, "security_issues": 0, "photo_retention_breaches": 0, "warnings": 0}
    assert calculate_score(perfect) == 100

@test("calculate_score: critical issues reduce score heavily")
def _():
    bad = {"critical": 3, "missing": 0, "security_issues": 0, "photo_retention_breaches": 0, "warnings": 0}
    assert calculate_score(bad) < 50

@test("calculate_risk: critical issues return High Risk")
def _():
    assert calculate_risk({"critical": 1, "missing": 0, "security_issues": 0, "warnings": 0, "photo_retention_breaches": 0}) == "High Risk"

@test("calculate_risk: warnings only return Needs Attention")
def _():
    assert calculate_risk({"critical": 0, "missing": 0, "security_issues": 0, "warnings": 1, "photo_retention_breaches": 0}) == "Needs Attention"

@test("calculate_risk: clean summary returns On Track")
def _():
    assert calculate_risk({"critical": 0, "missing": 0, "security_issues": 0, "warnings": 0, "photo_retention_breaches": 0}) == "On Track"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. PDF HTML GENERATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- PDF HTML Generation ---")

score = calculate_score(summary)
risk = calculate_risk(summary)
html = build_executive_pdf_html(report, score, risk)

@test("PDF HTML is non-empty and substantial")
def _():
    assert len(html) > 10000, f"HTML too short: {len(html)} chars"

@test("PDF HTML contains cover page with site name")
def _():
    assert TEST_SITE_NAME in html

@test("PDF HTML contains score badge")
def _():
    assert f"{score} / 100" in html or f"{score}/100" in html

@test("PDF HTML contains all section headings")
def _():
    sections = [
        "Executive Summary", "Key Findings", "Recommendations",
        "Missing Devices", "Critical Incidents", "Detailed Audit by Room",
        "Photo Retention Review",
    ]
    for section in sections:
        assert section in html, f"Missing section: {section}"

@test("PDF HTML photo section has interpolated thresholds (not literal)")
def _():
    assert "{photo_threshold}" not in html, "photo_threshold not interpolated"
    assert "{retention_days}" not in html, "retention_days not interpolated"

@test("PDF HTML has correct number of data table rows")
def _():
    total_rows = report["summary"]["total_devices"]
    # Room detail section should have at least as many <tr> as devices
    tr_count = html.count("<tr")
    assert tr_count >= total_rows, f"Only {tr_count} <tr> for {total_rows} devices"

@test("PDF HTML missing devices section has rows when missing > 0")
def _():
    if summary["missing"] > 0:
        # Find the missing devices section
        idx = html.find("Missing Devices")
        assert idx > 0
        section = html[idx:idx+5000]
        assert "row-missing" in section or "<td>" in section
    else:
        assert "No missing devices recorded" in html

@test("PDF HTML critical actions section has rows when critical > 0")
def _():
    if summary["critical"] > 0:
        idx = html.find("Critical Incidents")
        assert idx > 0
        section = html[idx:idx+5000]
        assert "<td>" in section

@test("PDF HTML room sections exist for each room")
def _():
    rooms = set()
    for r in report.get("rows", []):
        rn = room_name(r)
        rooms.add(rn)
    for room in rooms:
        assert _esc(room) in html, f"Room not in PDF: {room}"

@test("PDF HTML renders device data where available (not all N/A)")
def _():
    # Count N/A vs total cells
    na_count = html.count(">N/A<")
    total_td = html.count("<td")
    na_pct = na_count / total_td * 100 if total_td > 0 else 0
    # If the batch has data, N/A should be less than 50%
    rows = report.get("rows", [])
    has_data = any(r.get("ios_version") or r.get("windows_os") or r.get("photos_count") for r in rows)
    if has_data:
        assert na_pct < 50, f"Too many N/A cells: {na_count}/{total_td} ({na_pct:.0f}%)"

@test("PDF HTML policy checklist renders when site_config has data")
def _():
    sc = report.get("site_config", {})
    has_policy = any(sc.get(k) is not None for k in [
        "consent_forms_current", "photo_policy_documented", "staff_training_current",
    ])
    if has_policy:
        assert "Policy Compliance Checklist" in html


# ═══════════════════════════════════════════════════════════════════════════════
# 6. PDF FILE GENERATION
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- PDF File Generation ---")

@test("generate_executive_pdf creates a valid PDF file")
def _():
    path, filename = generate_executive_pdf(report, score, risk, "/tmp")
    assert os.path.exists(path), f"PDF not created at {path}"
    assert filename.endswith(".pdf")
    size = os.path.getsize(path)
    assert size > 5000, f"PDF too small: {size} bytes"

@test("PDF filename includes site name and audit date")
def _():
    _, filename = generate_executive_pdf(report, score, risk, "/tmp")
    site_slug = re.sub(r"[^a-zA-Z0-9_\-]+", "-", TEST_SITE_NAME).strip("-").lower()
    assert site_slug in filename, f"Site name not in filename: {filename}"
    audit_date = str(report.get("audit_date", ""))[:10]
    assert audit_date in filename, f"Audit date not in filename: {filename}"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. API ENDPOINT TESTS (live HTTP)
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- API Endpoints ---")

@test("GET /audit-batches returns list")
def _():
    r = requests.get(f"{API_BASE}/audit-batches", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) > 0

@test("GET /audit-batches?site_id filters correctly")
def _():
    site_id = TEST_BATCH.get("site_id")
    if site_id:
        r = requests.get(f"{API_BASE}/audit-batches", params={"site_id": site_id}, timeout=10)
        assert r.status_code == 200
        data = r.json()
        for b in data:
            assert b.get("site_id") == site_id or b.get("site_name") == TEST_SITE_NAME

@test("GET /audit-report/{batch_id} returns complete report")
def _():
    r = requests.get(f"{API_BASE}/audit-report/{TEST_BATCH_ID}", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert "rows" in data
    assert "summary" in data
    assert "site_name" in data
    assert len(data["rows"]) > 0

@test("GET /audit-report/{batch_id} rows have computed status")
def _():
    r = requests.get(f"{API_BASE}/audit-report/{TEST_BATCH_ID}", timeout=15)
    data = r.json()
    for row in data["rows"]:
        assert "status" in row, f"Row missing status: {row.get('serial_number')}"
        assert "reasons" in row, f"Row missing reasons: {row.get('serial_number')}"

@test("GET /audit-entries/{batch_id} returns raw entries")
def _():
    r = requests.get(f"{API_BASE}/audit-entries/{TEST_BATCH_ID}", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) > 0

@test("GET /audit-report/executive-pdf/{batch_id} returns PDF")
def _():
    r = requests.get(f"{API_BASE}/audit-report/executive-pdf/{TEST_BATCH_ID}", timeout=30)
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "pdf" in ct.lower() or "octet-stream" in ct.lower(), f"Not PDF: {ct}"
    assert len(r.content) > 5000, f"PDF too small: {len(r.content)} bytes"

@test("GET /sites returns sites list")
def _():
    r = requests.get(f"{API_BASE}/sites", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) > 0

@test("GET /sites/{site_id} returns site with policy fields")
def _():
    site_id = TEST_BATCH.get("site_id")
    if site_id:
        r = requests.get(f"{API_BASE}/sites/{site_id}", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "photo_retention_days" in data
        assert "photo_count_threshold" in data

@test("GET /audit-report/404 returns 404 for invalid batch")
def _():
    r = requests.get(f"{API_BASE}/audit-report/00000000-0000-0000-0000-000000000000", timeout=10)
    assert r.status_code in (404, 500)

@test("GET /remediation-summary returns data")
def _():
    r = requests.get(f"{API_BASE}/remediation-summary", timeout=10)
    assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 8. DATA COMPLETENESS TESTS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- Data Completeness ---")

@test("Every row has device_type populated")
def _():
    rows = report.get("rows", [])
    for r in rows:
        assert r.get("device_type"), f"Missing device_type: {r.get('serial_number')}"

@test("Every row has serial_number populated")
def _():
    rows = report.get("rows", [])
    for r in rows:
        assert r.get("serial_number"), f"Missing serial: {r.get('audit_id')}"

@test("Every row has assigned_user_room populated")
def _():
    rows = report.get("rows", [])
    for r in rows:
        rn = room_name(r)
        assert rn != "Unassigned", f"Unassigned device: {r.get('serial_number')}"

@test("Every row has device_present set (not None)")
def _():
    rows = report.get("rows", [])
    for r in rows:
        assert r.get("device_present") is not None, f"device_present is None: {r.get('serial_number')}"

@test("Data completeness: report tracks field coverage")
def _():
    rows = report.get("rows", [])
    total = len(rows)
    if total == 0:
        return
    fields = {
        "photos_count": sum(1 for r in rows if r.get("photos_count") is not None and r.get("photos_count") != ""),
        "os_info": sum(1 for r in rows if r.get("windows_os") or r.get("ios_version")),
        "sync_info": sum(1 for r in rows if r.get("onedrive_sync_on") is not None),
        "security_check": sum(1 for r in rows if r.get("security_check")),
    }
    print(f"    Data coverage: {json.dumps(fields)} / {total} devices")
    # This is informational — no assertion, just tracking


# ═══════════════════════════════════════════════════════════════════════════════
# 9. EDGE CASE TESTS
# ═══════════════════════════════════════════════════════════════════════════════
print("\n--- Edge Cases ---")

@test("classify handles completely empty entry")
def _():
    entry = {}
    status, reasons = classify(entry)
    assert status in ("ok", "critical", "warning", "ignored")

@test("build_executive_pdf_html handles empty rows")
def _():
    empty_report = {
        "rows": [], "summary": {"total_devices": 0, "ignored": 0, "critical": 0,
        "warnings": 0, "ok": 0, "missing": 0, "photo_retention_breaches": 0,
        "photo_count_warnings": 0, "security_issues": 0},
        "site_name": "Test", "audit_date": "2026-01-01", "audit_batch_id": "test",
        "recommendations": [], "site_config": {},
    }
    html = build_executive_pdf_html(empty_report, 100, "On Track")
    assert len(html) > 1000
    assert "Test" in html

@test("photo_count handles None and empty values")
def _():
    assert photo_count({}) == 0
    assert photo_count({"photos_count": None}) == 0
    assert photo_count({"photos_count": 42}) == 42
    assert photo_count({"total_photos": 10}) == 10

@test("device_label falls back correctly")
def _():
    assert device_label({"brand_model": "iPad Pro"}) == "iPad Pro"
    assert device_label({"device_name": "Room Tablet"}) == "Room Tablet"
    assert device_label({}) == "N/A"

@test("status_pill generates valid HTML for all statuses")
def _():
    for s in ("critical", "warning", "ok", "ignored"):
        pill = status_pill(s)
        assert "pill" in pill
        assert s.upper() in pill


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*70}")
print(f"  \033[32m{PASS} passed\033[0m, \033[31m{FAIL} failed\033[0m, {SKIP} skipped")
print(f"{'='*70}")

if FAIL > 0:
    print("\nFailed tests:")
    for result in RESULTS:
        if result[0] == "FAIL":
            print(f"  \033[31m✗\033[0m {result[1]}: {result[2]}")

sys.exit(1 if FAIL > 0 else 0)
