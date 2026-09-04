#!/usr/bin/env python3
"""
Action Tier Engine test suite (Phase 2 — "AI everywhere, humans for major change").

Covers tier classification, dry-run previews with rollback notes, tier-filtered
execution, the no-silent-action fallback, and the /api/autopilot/cases/{id}/execute
endpoint contract (gating, background execution, status/events).

Run:
  cd /home/aiagent/mission-control-ui && python3 scripts/test_tier_engine.py
"""
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ai_remediate as ar
import ai_resolver

# Redirect case/audit state to a temp dir so tests never touch live data.
TMP = Path("/tmp/soc_tier_engine_test")
TMP.mkdir(exist_ok=True)
ai_resolver.CASES_FILE = TMP / "ai_cases.json"
ai_resolver.AUDIT_FILE = TMP / "ai_audit_log.json"
ai_resolver.CASES_FILE.write_text("[]")
ai_resolver.AUDIT_FILE.write_text("[]")

from fastapi import FastAPI
from fastapi.testclient import TestClient
import soc_api

app = FastAPI()
app.include_router(soc_api.router)
client = TestClient(app)

MIXED_PLAN = [
    "notify SOC",
    {"type": "block_ip", "target": "10.99.0.9"},
    "Review alert details",
    "Isolate affected systems",
    {"type": "add_watchlist", "target": "203.0.113.7"},
]


class TierClassificationTests(unittest.TestCase):
    def test_action_tier_lookup(self):
        self.assertEqual(ar.action_tier("block_ip"), 2)
        self.assertEqual(ar.action_tier("notify"), 1)
        self.assertEqual(ar.action_tier("suppress_rule"), 1)
        self.assertEqual(ar.action_tier("isolate"), 2)
        self.assertEqual(ar.action_tier("revoke_session"), 2)
        self.assertEqual(ar.action_tier("require_mfa"), 2)
        self.assertEqual(ar.action_tier("delete_data"), 2)

    def test_action_tier_prefix_defaults(self):
        # informational step prefixes default to Tier 1
        self.assertEqual(ar.action_tier("review_alert_details"), 1)
        self.assertEqual(ar.action_tier("verify_alert_context"), 1)
        self.assertEqual(ar.action_tier("investigate_source"), 1)
        # unknown actions default to Tier 2 (conservative)
        self.assertEqual(ar.action_tier("foobar"), 2)
        self.assertEqual(ar.action_tier("isolate_affected_systems"), 2)

    def test_classify_case_splits_plan(self):
        case = {"id": "c-1", "response_plan": MIXED_PLAN}
        tiers = ar.classify_case(case)
        self.assertEqual(len(tiers["tier1"]), 3)  # notify, review, watchlist
        self.assertEqual(len(tiers["tier2"]), 2)  # block_ip, isolate
        t1 = [ar._normalize_action(a)[0] for a in tiers["tier1"]]
        t2 = [ar._normalize_action(a)[0] for a in tiers["tier2"]]
        self.assertIn("notify_soc", t1)
        self.assertIn("add_watchlist", t1)
        self.assertIn("block_ip", t2)
        self.assertIn("isolate_affected_systems", t2)

    def test_classify_handles_json_and_dict_plans(self):
        case = {"id": "c-2", "response_plan": json.dumps(MIXED_PLAN)}
        self.assertEqual(len(ar.classify_case(case)["tier1"]), 3)
        case2 = {"id": "c-3", "response_plan": {"actions": MIXED_PLAN}}
        self.assertEqual(len(ar.classify_case(case2)["tier2"]), 2)

    def test_rollback_notes(self):
        self.assertIn("iptables", ar.rollback_notes({"type": "block_ip"}))
        self.assertEqual(ar.rollback_notes("wibble"), ar.GENERIC_ROLLBACK)


class ExecutionTests(unittest.TestCase):
    def test_dry_run_never_executes(self):
        case = {"id": "c-10", "severity": "high", "title": "Dry", "response_plan": MIXED_PLAN}
        with mock.patch.object(ar, "block_ip", side_effect=AssertionError("executed!")), \
             mock.patch.object(ar, "notify_soc", side_effect=AssertionError("executed!")), \
             mock.patch.object(ar, "ping_device", side_effect=AssertionError("executed!")):
            results = ar.execute_case(case, dry_run=True)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r.get("dry_run") and r.get("rollback") for r in results))
        self.assertEqual(sorted(r["tier"] for r in results), [1, 1, 1, 2, 2])

    def test_tier1_filter_executes_only_tier1(self):
        case = {"id": "c-11", "severity": "high", "title": "T1", "response_plan": MIXED_PLAN}
        executed = []

        def _notify(*a, **k):
            executed.append("notify")
            return {"success": True, "action": "notify"}

        def _watch(*a, **k):
            executed.append("watchlist")
            return {"success": True, "action": "add_watchlist"}

        with mock.patch.object(ar, "notify_soc", side_effect=_notify), \
             mock.patch.object(ar, "add_watchlist", side_effect=_watch), \
             mock.patch.object(ar, "block_ip", side_effect=AssertionError("tier-2 ran!")), \
             mock.patch.object(ar, "ping_device", side_effect=AssertionError("unknown ran!")):
            results = ar.execute_case(case, tier=1)
        self.assertIn("notify", executed)
        self.assertIn("watchlist", executed)
        self.assertEqual(len(executed), 3)
        self.assertTrue(all(r.get("success") for r in results))

    def test_tier2_filter_executes_only_tier2(self):
        case = {"id": "c-12", "severity": "high", "title": "T2", "response_plan": MIXED_PLAN}
        with mock.patch.object(ar, "block_ip", return_value={"success": True, "action": "block_ip"}), \
             mock.patch.object(ar, "notify_soc", return_value={"success": True, "action": "notify"}) as nf:
            results = ar.execute_case(case, tier=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["action"], "block_ip")
        nf.assert_called_once()

    def test_unknown_action_with_target_never_silently_pings(self):
        case = {"id": "c-13", "severity": "medium", "title": "U",
                "response_plan": [{"type": "weird_thing", "target": "10.1.1.1"}]}
        with mock.patch.object(ar, "ping_device", side_effect=AssertionError("pinged without a known action!")):
            results = ar.execute_case(case, tier=None)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["success"])
        self.assertIn("human review required", results[0]["error"])

    def test_no_plan_default_notify_and_empty_tier(self):
        case = {"id": "c-14", "severity": "low", "title": "Empty"}
        with mock.patch.object(ar, "notify_soc", return_value={"success": True}) as nf:
            self.assertEqual(len(ar.execute_case(case, tier=None)), 1)
        nf.assert_called_once()
        case2 = {"id": "c-15", "severity": "low", "title": "OnlyT2",
                 "response_plan": [{"type": "block_ip", "target": "1.2.3.4"}]}
        with mock.patch.object(ar, "notify_soc", side_effect=AssertionError("default notify ran for empty tier-1")):
            self.assertEqual(ar.execute_case(case2, tier=1), [])


def make_test_case():
    analysis = {"analysis": "Tier API test", "confidence": 0.9,
                "recommended_action": "escalate", "mitre_technique": "T1078",
                "response_plan": MIXED_PLAN, "false_positive_likelihood": "low"}
    cid = ai_resolver.create_case(
        [{"id": "a-99", "title": "Tier API test alert", "level": 13,
          "source": "test-agent", "rule_id": 999}], analysis)
    assert cid is not None
    return cid


class ExecuteEndpointTests(unittest.TestCase):
    def _make_case(self):
        return make_test_case()

    def test_execute_gating_and_lifecycle(self):
        cid = self._make_case()
        # unapproved -> gated
        r = client.post(f"/api/autopilot/cases/{cid}/execute")
        self.assertEqual(r.json()["status"], "error")
        self.assertIn("must be approved", r.json()["message"])
        # approve -> audit event
        r = client.post(f"/api/autopilot/cases/{cid}/approve")
        self.assertEqual(r.json()["case"]["status"], "approved")
        self.assertTrue(any(e["type"] == "approved" for e in ai_resolver.get_case(cid).get("events", [])))
        # execute with executors mocked (no iptables/telegram side effects)
        with mock.patch.object(ar, "block_ip", return_value={"success": True, "action": "block_ip", "target": "10.99.0.9"}), \
             mock.patch.object(ar, "notify_soc", return_value={"success": True, "action": "notify"}):
            r = client.post(f"/api/autopilot/cases/{cid}/execute")
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["gated_actions"], 2)
        self.assertEqual(len(body["plan"]), 2)
        self.assertTrue(all(p.get("rollback") for p in body["plan"]))
        self.assertEqual(body["plan"][0]["type"], "block_ip")
        # background thread completes -> resolved + actions + events
        deadline = time.time() + 10
        c = None
        while time.time() < deadline:
            c = ai_resolver.get_case(cid)
            if c.get("status") == "resolved":
                break
            time.sleep(0.2)
        self.assertEqual(c["status"], "resolved")
        self.assertEqual(len(c.get("actions", [])), 2)
        self.assertEqual(c["actions"][0]["action"], "block_ip")
        self.assertTrue(c["actions"][0]["success"])
        self.assertTrue(any(e["type"] == "executed" for e in c.get("events", [])))
        self.assertTrue(c.get("executed_at"))

    def test_execute_missing_case(self):
        r = client.post("/api/autopilot/cases/does-not-exist/execute")
        self.assertEqual(r.json()["status"], "error")
        self.assertEqual(r.json()["message"], "case not found")


class ScannerIntegrationTests(unittest.TestCase):
    def test_scan_tier1_helper(self):
        import app as app_mod
        cid = make_test_case()
        primary = {"id": "a-99", "title": "Tier API test alert", "level": 13}
        with mock.patch.object(ar, "notify_soc", return_value={"success": True, "action": "notify"}), \
             mock.patch.object(ar, "add_watchlist", return_value={"success": True, "action": "add_watchlist"}), \
             mock.patch.object(ar, "block_ip", side_effect=AssertionError("tier-2 ran in tier-1 helper!")):
            app_mod._run_tier1_actions(cid, primary, 13, 0.9)
        c = ai_resolver.get_case(cid)
        t1 = c.get("tier1_actions", [])
        self.assertEqual(len(t1), 3)
        self.assertTrue(all(r.get("success") for r in t1))
        self.assertTrue(any(e["type"] == "tier1_auto_executed" for e in c.get("events", [])))
        audit = json.loads(ai_resolver.AUDIT_FILE.read_text())
        self.assertTrue(any(e.get("action") == "tier1_auto_executed" for e in audit))
        self.assertFalse(any(r.get("action") == "block_ip" for r in t1))
        self.assertEqual(c["status"], "awaiting_approval")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(TierClassificationTests),
        loader.loadTestsFromTestCase(ExecutionTests),
        loader.loadTestsFromTestCase(ExecuteEndpointTests),
        loader.loadTestsFromTestCase(ScannerIntegrationTests),
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)