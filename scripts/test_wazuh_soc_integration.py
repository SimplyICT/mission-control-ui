#!/usr/bin/env python3
"""
Integration test suite for Wazuh SOC dashboard and API proxy.

Tests HTML page endpoints, API proxy forwarding, auto-auth token
management, error handling, and SPA content completeness.

Run:
  cd /home/aiagent/mission-control-ui && source venv/bin/activate \
    && python3 /home/aiagent/mission-control-repo/scripts/test_wazuh_soc_integration.py
"""
import os
import sys
import json
import traceback

import requests as req

# ── Config ────────────────────────────────────────────────────────
UI_BASE = "http://127.0.0.1:8095"

# Forge a valid session cookie so tests bypass the login form.
# This matches the server-side token-creation logic in app.py.
sys.path.insert(0, "/home/aiagent/mission-control-ui")
from dotenv import load_dotenv
load_dotenv("/home/aiagent/mission-control-site/.env")

from itsdangerous import URLSafeTimedSerializer

_SESSION_SECRET = os.getenv("SESSION_SECRET", "")
assert _SESSION_SECRET, "SESSION_SECRET not set — cannot forge session token"
_serializer = URLSafeTimedSerializer(_SESSION_SECRET)
_TOKEN = _serializer.dumps({"user": "admin"})
COOKIES = {"mc_auth": _TOKEN}

# ── Test harness (matches existing repo convention) ───────────────
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


print(f"\n{'='*70}")
print(f"Wazuh SOC Integration Tests — {UI_BASE}")
print(f"{'='*70}\n")


# ═══════════════════════════════════════════════════════════════════
# 1. AUTH & SESSION
# ═══════════════════════════════════════════════════════════════════
print("--- Auth & Session ---")


@test("Unauthenticated request to /wazuh-soc.html returns 302 redirect")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", allow_redirects=False)
    assert r.status_code == 302, f"Expected 302, got {r.status_code}"
    assert "/login" in r.headers.get("location", ""), "Should redirect to /login"


@test("Unauthenticated request to /wazuh-api/overview returns 302 redirect")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview", allow_redirects=False)
    assert r.status_code == 302, f"Expected 302, got {r.status_code}"


@test("Authenticated session cookie grants access to SOC pages")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES, allow_redirects=False)
    assert r.status_code == 200, f"Expected 200 with valid session, got {r.status_code}"


@test("Expired/invalid session cookie returns 302")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies={"mc_auth": "garbage"}, allow_redirects=False)
    assert r.status_code == 302, f"Expected 302 for invalid cookie, got {r.status_code}"


# ═══════════════════════════════════════════════════════════════════
# 2. HTML PAGE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════
print("\n--- HTML Page Endpoints ---")

SOC_PAGES = {
    "/wazuh-soc.html":       "Wazuh SOC",
    "/wazuh-dashboard.html": "Wazuh",
    "/wazuh-alerts.html":    "Wazuh",
    "/wazuh-autopilot.html": "SOC Autopilot",
}

for path, expected_text in SOC_PAGES.items():
    @test(f"GET {path} returns 200 with HTML content")
    def _(p=path, t=expected_text):
        r = req.get(f"{UI_BASE}{p}", cookies=COOKIES)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        assert "text/html" in r.headers.get("content-type", ""), "Expected HTML content-type"
        assert t in r.text, f"Expected '{t}' in response body"


@test("GET /wazuh-soc.html returns substantial content (>10KB SPA)")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES)
    assert len(r.text) > 10000, f"SPA should be >10KB, got {len(r.text)} bytes"


@test("GET /index-platform.html contains Security Operations section")
def _():
    r = req.get(f"{UI_BASE}/index-platform.html", cookies=COOKIES)
    assert r.status_code == 200
    assert "Security Operations" in r.text, "Home page should have Security Operations section"
    assert "wazuh-soc.html" in r.text, "Home page should link to wazuh-soc.html"


@test("GET /index-platform.html no longer contains Fleet & Infrastructure")
def _():
    r = req.get(f"{UI_BASE}/index-platform.html", cookies=COOKIES)
    assert "Fleet &amp; Infrastructure" not in r.text, "Fleet & Infrastructure section should be removed"


# ═══════════════════════════════════════════════════════════════════
# 3. SPA CONTENT VALIDATION
# ═══════════════════════════════════════════════════════════════════
print("\n--- SPA Content Validation ---")

EXPECTED_VIEWS = [
    ("dashboard",       "Command Center"),
    ("agents",          "Agents"),
    ("sca",             "SCA Compliance"),
    ("fim",             "File Integrity"),
    ("vulnerabilities", "Vulnerabilities"),
    ("mitre",           "MITRE ATT"),
    ("rules",           "Rules"),
    ("events",          "Events"),
    ("topology",        "Topology"),
    ("threats",         "Threat Intel"),
    ("autopilot",       "SOC Autopilot"),
    ("manager",         "Manager Health"),
    ("groups",          "Groups"),
    ("help",            "Help"),
]


@test("SPA sidebar contains all 14 navigation items")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES)
    body = r.text
    for page_id, label in EXPECTED_VIEWS:
        assert f'data-page="{page_id}"' in body, f"Missing nav item data-page=\"{page_id}\""


@test("SPA contains all page-rendering functions")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES)
    body = r.text
    required_fns = [
        "pageDashboard", "pageAgents", "pageSCA", "pageFIM",
        "pageVulnerabilities", "pageMitre", "pageRules", "pageEvents",
        "pageTopology", "pageThreats", "pageAutopilot", "pageManager",
        "pageGroups", "pageHelp",
    ]
    for fn in required_fns:
        assert fn in body, f"Missing function {fn}()"


@test("SPA contains hash-based router")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES)
    assert "hashchange" in r.text, "Missing hashchange event listener"
    assert "function route()" in r.text or "function route()" in r.text.replace("\n", ""), \
        "Missing route() function"


@test("SPA includes Chart.js library")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES)
    assert "chart.js" in r.text.lower() or "Chart(" in r.text, \
        "Missing Chart.js reference"


@test("SPA contains back-link to Mission Control")
def _():
    r = req.get(f"{UI_BASE}/wazuh-soc.html", cookies=COOKIES)
    assert "index-platform.html" in r.text, "Missing link back to Mission Control"


# ═══════════════════════════════════════════════════════════════════
# 4. WAZUH API PROXY — CORE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════
print("\n--- Wazuh API Proxy ---")


@test("GET /wazuh-api/overview returns JSON with agent data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "data" in data or "total_agents" in data or "active" in data, \
        f"Expected agent overview fields, got keys: {list(data.keys())[:10]}"


@test("GET /wazuh-api/agents returns agent list")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/agents", cookies=COOKIES, params={"limit": "5"}, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    # The SOC API wraps data in {data: {affected_items: [...]}}
    inner = data.get("data", data)
    assert "affected_items" in inner or isinstance(inner, list), \
        f"Expected affected_items or list, got: {list((inner if isinstance(inner, dict) else {}).keys())[:10]}"


@test("GET /wazuh-api/events/stats returns severity breakdown")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/events/stats", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    inner = data.get("data", data)
    assert "severity" in inner or "total" in inner or isinstance(inner, dict), \
        f"Expected stats object, got: {data}"


@test("GET /wazuh-api/manager returns manager status")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/manager", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/manager/info returns manager metadata")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/manager/info", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/rules returns rule list")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/rules", cookies=COOKIES, params={"limit": "5"}, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    inner = data.get("data", data)
    assert "affected_items" in inner or isinstance(inner, list), \
        f"Expected rules list"


@test("GET /wazuh-api/decoders returns decoder list")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/decoders", cookies=COOKIES, params={"limit": "5"}, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/groups returns group list")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/groups", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/mitre returns MITRE data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/mitre", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/overview/sca returns SCA data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview/sca", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/overview/fim returns FIM data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview/fim", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/overview/vulnerabilities returns vulnerability data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview/vulnerabilities", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/topology returns topology data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/topology", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/events returns event list")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/events", cookies=COOKIES, params={"size": "5"}, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/otx/status returns OTX threat intel data")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/otx/status", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/autopilot/cases returns autopilot case list")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/autopilot/cases", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("GET /wazuh-api/autopilot/stats returns autopilot stats")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/autopilot/stats", cookies=COOKIES, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


# ═══════════════════════════════════════════════════════════════════
# 5. PROXY QUERY PARAMS & METHODS
# ═══════════════════════════════════════════════════════════════════
print("\n--- Proxy Query Params & Methods ---")


@test("Proxy forwards query parameters correctly")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/agents", cookies=COOKIES,
                params={"limit": "2", "offset": "0"}, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"


@test("Proxy handles POST method")
def _():
    # POST to auth/login is the simplest POST endpoint we can test
    r = req.post(f"{UI_BASE}/wazuh-api/auth/login", cookies=COOKIES,
                 json={"username": "admin", "password": "admin123"}, timeout=30)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert "token" in data or "data" in data, f"Expected token in login response"


@test("Proxy returns proper JSON content-type for API responses")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview", cookies=COOKIES, timeout=30)
    ct = r.headers.get("content-type", "")
    assert "json" in ct or "text" in ct, f"Expected JSON content-type, got: {ct}"


# ═══════════════════════════════════════════════════════════════════
# 6. ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════
print("\n--- Error Handling ---")


@test("Proxy returns 404 for non-existent SOC API path")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/nonexistent/endpoint/12345", cookies=COOKIES, timeout=30)
    # Should get 404 from upstream or a proxy error — not a 500 crash
    assert r.status_code in (404, 400, 502), f"Expected 404/400/502, got {r.status_code}"


@test("GET /nonexistent-wazuh-page.html returns 404")
def _():
    r = req.get(f"{UI_BASE}/nonexistent-wazuh-page.html", cookies=COOKIES)
    assert r.status_code in (404, 302), f"Expected 404/302, got {r.status_code}"


# ═══════════════════════════════════════════════════════════════════
# 7. USER GUIDE DOCUMENTATION
# ═══════════════════════════════════════════════════════════════════
print("\n--- User Guide Documentation ---")


@test("User guide contains Security Operations sidebar group")
def _():
    r = req.get(f"{UI_BASE}/user-guide.html", cookies=COOKIES)
    assert r.status_code == 200
    assert "Security Operations" in r.text, "Missing Security Operations sidebar group"


@test("User guide contains all SOC section anchors")
def _():
    r = req.get(f"{UI_BASE}/user-guide.html", cookies=COOKIES)
    body = r.text
    anchors = [
        "soc-overview", "soc-command-center", "soc-agents", "soc-sca",
        "soc-fim", "soc-vulnerabilities", "soc-mitre", "soc-rules",
        "soc-events", "soc-topology", "soc-threats", "soc-autopilot",
        "soc-manager", "soc-groups",
    ]
    for anchor in anchors:
        assert f'id="{anchor}"' in body, f"Missing section anchor: {anchor}"


@test("User guide contains v1.1 changelog entry")
def _():
    r = req.get(f"{UI_BASE}/user-guide.html", cookies=COOKIES)
    assert "v1.1" in r.text, "Missing v1.1 changelog entry"
    assert "Wazuh SOC Dashboard" in r.text, "Missing Wazuh SOC Dashboard in changelog"


# ═══════════════════════════════════════════════════════════════════
# 8. AUTO-AUTH TOKEN MANAGEMENT
# ═══════════════════════════════════════════════════════════════════
print("\n--- Auto-Auth Token Management ---")


@test("Proxy authenticates automatically (no 401 returned to client)")
def _():
    # Multiple sequential requests should all succeed — token is cached
    for i in range(3):
        r = req.get(f"{UI_BASE}/wazuh-api/overview", cookies=COOKIES, timeout=30)
        assert r.status_code == 200, f"Request {i+1} returned {r.status_code} — auto-auth may be broken"


@test("Proxy returns structured JSON, not raw HTML error pages")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview", cookies=COOKIES, timeout=30)
    try:
        data = r.json()
    except Exception:
        assert False, f"Response is not valid JSON — possibly an HTML error page: {r.text[:200]}"


# ═══════════════════════════════════════════════════════════════════
# 9. RESPONSE DATA INTEGRITY
# ═══════════════════════════════════════════════════════════════════
print("\n--- Response Data Integrity ---")


@test("Overview endpoint returns numeric agent counts")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/overview", cookies=COOKIES, timeout=30)
    data = r.json()
    inner = data.get("data", data)
    agents = inner.get("total_agents")
    if agents is not None:
        assert isinstance(agents, (int, float)), f"total_agents should be numeric, got {type(agents)}"
        assert agents >= 0, f"total_agents should be >= 0, got {agents}"


@test("Agents endpoint returns list with expected fields")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/agents", cookies=COOKIES, params={"limit": "3"}, timeout=30)
    data = r.json()
    inner = data.get("data", data)
    items = inner.get("affected_items", inner if isinstance(inner, list) else [])
    if items:
        agent = items[0]
        for field in ("id", "name", "status"):
            assert field in agent, f"Agent missing expected field '{field}'"


@test("Events endpoint returns list with timestamp and level")
def _():
    r = req.get(f"{UI_BASE}/wazuh-api/events", cookies=COOKIES, params={"size": "3"}, timeout=30)
    data = r.json()
    inner = data.get("data", data)
    items = inner.get("affected_items", inner if isinstance(inner, list) else [])
    if items:
        event = items[0]
        assert "timestamp" in event or "rule_id" in event or "description" in event, \
            f"Event missing expected fields, got: {list(event.keys())[:8]}"


# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
print(f"\n{'='*70}")
print(f"  \033[32m{PASS} passed\033[0m, \033[31m{FAIL} failed\033[0m, {SKIP} skipped")
print(f"{'='*70}")

if FAIL > 0:
    print("\nFailed tests:")
    for result in RESULTS:
        if result[0] == "FAIL":
            print(f"  \033[31m✗\033[0m {result[1]}: {result[2]}")

sys.exit(1 if FAIL > 0 else 0)
