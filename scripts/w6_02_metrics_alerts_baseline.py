#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib
import shutil
import urllib.request
import urllib.error


def probe(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"ok": True, "status_code": resp.getcode(), "body": body[:500], "error": ""}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "status_code": exc.code, "body": body[:500], "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "status_code": None, "body": "", "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate W6-02 metrics and alerts baseline artifact")
    parser.add_argument("--artifacts-dir", default="/home/aiagent/mission-control-ui/project-tracker/artifacts")
    parser.add_argument("--platform-health-url", default="http://127.0.0.1:8095/health")
    parser.add_argument("--audit-api-url", default="http://127.0.0.1:8096/")
    parser.add_argument("--candidate", default="W6-02-baseline")
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    artifacts_dir = pathlib.Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_file = artifacts_dir / f"w6-02-metrics-alerts-baseline-{stamp}.json"
    latest_file = artifacts_dir / "w6-02-metrics-alerts-baseline-latest.json"

    platform = probe(args.platform_health_url)
    audit = probe(args.audit_api_url)

    baseline = {
        "task_id": "W6-02",
        "generated_at": now.isoformat(),
        "candidate": args.candidate,
        "probes": [
            {"name": "platform_health", "url": args.platform_health_url, **platform},
            {"name": "audit_api_root", "url": args.audit_api_url, **audit},
        ],
        "alert_policy_baseline": {
            "uptime": {
                "check_interval_seconds": 60,
                "trigger_condition": "3 consecutive probe failures",
                "severity": "critical"
            },
            "error_rate": {
                "window_minutes": 5,
                "warning_threshold_percent": 3.0,
                "critical_threshold_percent": 5.0,
                "severity": "warning_or_critical"
            },
            "latency_p95": {
                "window_minutes": 15,
                "warning_threshold_ms": 800,
                "critical_threshold_ms": 1500,
                "severity": "warning_or_critical"
            },
            "structured_log_failures": {
                "window_minutes": 10,
                "trigger_condition": "missing required JSON fields in >=10 events",
                "severity": "warning"
            }
        },
        "implementation_notes": [
            "Baseline thresholds defined for uptime, error rate, and latency p95.",
            "Health probes captured at generation time for platform and audit services.",
            "Next step: wire threshold evaluation into monitor pipeline and notification channel."
        ]
    }

    out_file.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(out_file, latest_file)
    print(str(out_file))


if __name__ == "__main__":
    main()
