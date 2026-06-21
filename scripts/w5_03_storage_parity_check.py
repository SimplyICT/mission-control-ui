#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib
import shutil
import urllib.request
import urllib.error


def http_probe(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return {
                "ok": True,
                "status_code": resp.getcode(),
                "reason": "reachable",
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": exc.code in (200, 204, 401, 403),
            "status_code": exc.code,
            "reason": f"http_error_{exc.code}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "status_code": None,
            "reason": str(exc),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run W5-03 storage/object migration parity checks")
    parser.add_argument(
        "--artifacts-dir",
        default="/home/aiagent/mission-control-ui/project-tracker/artifacts",
        help="Directory where report artifacts will be written",
    )
    parser.add_argument(
        "--platform-health-url",
        default="http://127.0.0.1:8095/health",
        help="Platform service health probe URL",
    )
    parser.add_argument(
        "--candidate",
        default="W5-03-baseline",
        help="Candidate label for this parity run",
    )
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    artifacts_dir = pathlib.Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    report_path = artifacts_dir / f"w5-03-storage-parity-report-{stamp}.json"
    latest_path = artifacts_dir / "w5-03-storage-parity-report-latest.json"

    write_probe_path = artifacts_dir / ".w5-03-write-probe"
    try:
        write_probe_path.write_text("ok\n", encoding="utf-8")
        write_probe_path.unlink(missing_ok=True)
        artifacts_write_ok = True
        artifacts_write_reason = "writable"
    except Exception as exc:
        artifacts_write_ok = False
        artifacts_write_reason = str(exc)

    health = http_probe(args.platform_health_url)

    checks = [
        {
            "id": "artifacts_directory_writable",
            "description": "Tracker artifacts directory accepts writes for parity outputs",
            "status": "pass" if artifacts_write_ok else "fail",
            "details": {"reason": artifacts_write_reason},
        },
        {
            "id": "platform_health_reachable",
            "description": "Platform service health endpoint responds",
            "status": "pass" if health["ok"] else "fail",
            "details": health,
        },
        {
            "id": "object_upload_contract",
            "description": "Verify upload endpoint supports required metadata and content-type parity",
            "status": "manual_required",
            "details": {
                "expected": ["content_type", "object_key", "checksum", "size_bytes"],
                "next_action": "Run authenticated upload contract tests against platform-api image/object endpoint",
            },
        },
        {
            "id": "object_download_contract",
            "description": "Verify download/read access parity and object path resolution",
            "status": "manual_required",
            "details": {
                "expected": ["authorized_read", "forbidden_read", "path_mapping"],
                "next_action": "Run authenticated read tests against platform-api signed URL/read path",
            },
        },
        {
            "id": "signed_url_ttl_and_acl",
            "description": "Verify signed URL TTL boundaries and ACL equivalence",
            "status": "manual_required",
            "details": {
                "expected": ["min_ttl", "max_ttl", "expired_url_rejected", "role_restrictions"],
                "next_action": "Execute signed URL issuance and expiry tests",
            },
        },
        {
            "id": "metadata_roundtrip_parity",
            "description": "Verify metadata write/read parity across legacy and new object paths",
            "status": "manual_required",
            "details": {
                "expected": ["filename", "mime_type", "owner_reference", "created_at"],
                "next_action": "Compare persisted metadata rows with legacy object metadata samples",
            },
        },
        {
            "id": "delete_lifecycle_parity",
            "description": "Verify object deletion lifecycle and orphan cleanup parity",
            "status": "manual_required",
            "details": {
                "expected": ["soft_delete_or_hard_delete_policy", "metadata_consistency", "audit_event"],
                "next_action": "Run delete flow tests and verify audit/log outputs",
            },
        },
    ]

    failed = [c for c in checks if c["status"] == "fail"]
    manual = [c for c in checks if c["status"] == "manual_required"]
    passed = [c for c in checks if c["status"] == "pass"]

    report = {
        "task_id": "W5-03",
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
