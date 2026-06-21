#!/usr/bin/env python3
"""
Supabase daily backup — exports all tables to a compressed JSON archive.
Keeps 30 days of rolling backups in ~/supabase-backups/
"""

import os, json, gzip, tarfile, logging, sys
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# ── Config ────────────────────────────────────────────────────────────────────
ENV_FILE   = Path("/home/aiagent/mission-control-site/.env")
BACKUP_DIR = Path("/home/aiagent/supabase-backups")
KEEP_DAYS  = 30
TABLES     = [
    "sites",
    "devices",
    "device_audits",
    "audit_entries",
    "remediation_actions",
    "incidents",
]
PAGE_SIZE  = 1000  # Supabase default max rows per request

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BACKUP_DIR / "backup.log"),
    ],
)
log = logging.getLogger("supabase_backup")


def load_env():
    load_dotenv(ENV_FILE)
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not url or not key:
        raise RuntimeError("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not found in .env")
    return url, key


def fetch_table(client, table_name: str) -> list:
    """Fetch all rows from a table using pagination."""
    rows = []
    offset = 0
    while True:
        result = (
            client.table(table_name)
            .select("*")
            .range(offset, offset + PAGE_SIZE - 1)
            .execute()
        )
        batch = result.data or []
        rows.extend(batch)
        if len(batch) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return rows


def run_backup():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Loading Supabase credentials...")
    url, key = load_env()

    from supabase import create_client
    client = create_client(url, key)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    backup_name = f"supabase-backup-{timestamp}"
    tmp_dir = BACKUP_DIR / backup_name
    tmp_dir.mkdir()

    total_rows = 0
    manifest = {"timestamp": timestamp, "tables": {}}

    for table in TABLES:
        log.info(f"Exporting table: {table}")
        try:
            rows = fetch_table(client, table)
            out_file = tmp_dir / f"{table}.json.gz"
            with gzip.open(out_file, "wt", encoding="utf-8") as f:
                json.dump(rows, f, default=str)
            manifest["tables"][table] = {"rows": len(rows), "file": f"{table}.json.gz"}
            log.info(f"  → {len(rows)} rows")
            total_rows += len(rows)
        except Exception as e:
            log.error(f"  ✗ Failed to export {table}: {e}")
            manifest["tables"][table] = {"error": str(e)}

    manifest["total_rows"] = total_rows

    # Write manifest
    with open(tmp_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    # Bundle into .tar.gz
    archive_path = BACKUP_DIR / f"{backup_name}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(tmp_dir, arcname=backup_name)

    # Clean up temp dir
    import shutil
    shutil.rmtree(tmp_dir)

    log.info(f"Backup complete: {archive_path.name} ({total_rows} total rows)")

    # ── Rolling retention: remove backups older than KEEP_DAYS ────────────────
    cutoff = datetime.now(timezone.utc).timestamp() - (KEEP_DAYS * 86400)
    for old in BACKUP_DIR.glob("supabase-backup-*.tar.gz"):
        if old.stat().st_mtime < cutoff:
            old.unlink()
            log.info(f"Deleted old backup: {old.name}")

    return archive_path


if __name__ == "__main__":
    try:
        path = run_backup()
        log.info(f"SUCCESS: {path}")
        sys.exit(0)
    except Exception as e:
        log.error(f"BACKUP FAILED: {e}")
        sys.exit(1)
