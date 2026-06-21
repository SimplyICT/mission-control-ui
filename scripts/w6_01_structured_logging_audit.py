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
        return {"ok": exc.code in (200, 401, 403), "status_code": exc.code, "body": body[:500], "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "status_code": None, "body": "", "error": str(exc)}


def classify_log_line(line: str) -> str:
    line = line.strip()
    if not line:
        return "empty"
    if line.startswith("{") and line.endswith("}"):
        try:
            json.loads(line)
            return "json"
        except Exception:
            return "text"
    return "text"


def load_recent_lines(log_path: pathlib.Path, max_lines: int = 200) -> list[str]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def main() -> None:
    parser = argparse.ArgumentParser(description="W6-01 structured logging parity audit")
    parser.add_argument("--ui-log", default="/home/aiagent/mission-control-ui/ui.log")
    parser.add_argument("--artifacts-dir", default="/home/aiagent/mission-control-ui/project-tracker/artifacts")
    parser.add_argument("--health-url", default="http://127.0.0.1:8095/health")
    parser.add_argument("--candidate", default="W6-01-baseline")
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    artifacts_dir = pathlib.Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifacts_dir / f"w6-01-structured-logging-audit-{stamp}.json"
    latest_path = artifacts_dir / "w6-01-structured-logging-audit-latest.json"

    log_path = pathlib.Path(args.ui_log)
    recent_lines = load_recent_lines(log_path)
    categories = {"json": 0, "text": 0, "empty": 0}
    for line in recent_lines:
        categories[classify_log_line(line)] += 1

    health = probe(args.health_url)
    json_ratio = (categories["json"] / len(recent_lines)) if recent_lines else 0.0

    checks = [
        {
            "id": "service_health_reachable",
            "status": "pass" if health["ok"] else "fail",
            "details": health,
        },
        {
            "id": "log_file_present",
            "status": "pass" if log_path.exists() else "fail",
            "details": {"path": str(log_path), "exists": log_path.exists()},
        },
        {
            "id": "json_log_ratio",
            "status": "pass" if json_ratio >= 0.8 else "manual_required",
            "details": {"ratio": round(json_ratio, 3), "counts": categories, "sample_size": len(recent_lines)},
        },
        {
            "id": "required_schema_fields",
            "status": "manual_required",
            "details": {
                "expected": ["timestamp", "level", "event", "requestId", "method", "path", "statusCode", "durationMs"],
                "next_action": "Instrument request middleware/events to emit JSON records with full schema",
            },
        },
    ]

    failed = [c for c in checks if c["status"] == "fail"]
    manual = [c for c in checks if c["status"] == "manual_required"]
    passed = [c for c in checks if c["status"] == "pass"]

    report = {
        "task_id": "W6-01",
        "candidate": args.candidate,
        "generated_at": now.isoformat(),
        "summary": {
            "total_checks": len(checks),
            "passed": len(passed),
            "failed": len(failed),
            "manual_required": len(manual),
            "overall_status": "fail" if failed else "pending_manual_validation",
        },
        "checks": checks,
    }

    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(report_path, latest_path)
    print(str(report_path))


if __name__ == "__main__":
    main()
