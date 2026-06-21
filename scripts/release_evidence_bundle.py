#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib
import subprocess
from typing import Any, Dict, List

REPO_ROOT = pathlib.Path('/home/aiagent/mission-control-repo')
TRACKER_PATH = pathlib.Path('/home/aiagent/mission-control-ui/project-tracker/tasks.json')
OUT_DIR = REPO_ROOT / 'release-evidence'


def run_cmd(cmd: List[str], cwd: pathlib.Path | None = None) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return {
            'ok': result.returncode == 0,
            'return_code': result.returncode,
            'stdout': result.stdout.strip(),
            'stderr': result.stderr.strip(),
            'command': ' '.join(cmd),
        }
    except Exception as exc:
        return {
            'ok': False,
            'return_code': -1,
            'stdout': '',
            'stderr': str(exc),
            'command': ' '.join(cmd),
        }


def service_state(service: str) -> Dict[str, Any]:
    state = run_cmd(['systemctl', 'is-active', service])
    return {
        'service': service,
        'active': state['stdout'] == 'active' and state['ok'],
        'state': state['stdout'] or 'unknown',
        'diagnostic': state['stderr'],
    }


def http_health(url: str) -> Dict[str, Any]:
    check = run_cmd(['curl', '-fsS', '-m', '5', url])
    return {
        'url': url,
        'healthy': check['ok'],
        'response': check['stdout'][:500],
        'error': check['stderr'],
    }


def tracker_snapshot() -> Dict[str, Any]:
    if not TRACKER_PATH.exists():
        return {'exists': False}
    data = json.loads(TRACKER_PATH.read_text(encoding='utf-8'))
    tasks = data.get('tasks', [])
    by_status: Dict[str, int] = {}
    for task in tasks:
        status = task.get('status', 'unknown')
        by_status[status] = by_status.get(status, 0) + 1
    return {
        'exists': True,
        'path': str(TRACKER_PATH),
        'meta_last_updated': data.get('meta', {}).get('last_updated'),
        'task_count': len(tasks),
        'status_counts': by_status,
    }


def latest_ci_signal() -> Dict[str, Any]:
    api = run_cmd(['gh', 'api', '/repos/SimplyICT/SimplyClik/actions/runs?per_page=10'])
    if not api['ok']:
        return {'available': False, 'error': api['stderr'] or api['stdout']}
    payload = json.loads(api['stdout'] or '{}')
    runs = payload.get('workflow_runs', [])
    for run in runs:
        if run.get('name') == 'CI':
            return {
                'available': True,
                'id': run.get('id'),
                'head_branch': run.get('head_branch'),
                'conclusion': run.get('conclusion'),
                'html_url': run.get('html_url'),
                'updated_at': run.get('updated_at'),
            }
    return {'available': False, 'error': 'No CI runs found in sampled history'}


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate release evidence bundle JSON artifact')
    parser.add_argument('--candidate', default='unspecified', help='Release candidate label or tag')
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.strftime('%Y%m%dT%H%M%SZ')

    git_head = run_cmd(['git', 'rev-parse', 'HEAD'], cwd=REPO_ROOT)
    git_branch = run_cmd(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=REPO_ROOT)
    git_status = run_cmd(['git', 'status', '--porcelain'], cwd=REPO_ROOT)

    bundle = {
        'generated_at': now.isoformat(),
        'candidate': args.candidate,
        'repo': {
            'path': str(REPO_ROOT),
            'branch': git_branch.get('stdout', ''),
            'head': git_head.get('stdout', ''),
            'clean_worktree': git_status.get('stdout', '') == '',
            'status_porcelain': git_status.get('stdout', ''),
        },
        'services': [
            service_state('mission-control-ui'),
            service_state('device-audit-api'),
            service_state('nginx'),
        ],
        'health_checks': [
            http_health('http://127.0.0.1:8095/health'),
            http_health('http://127.0.0.1:8096/'),
        ],
        'tracker': tracker_snapshot(),
        'ci_latest': latest_ci_signal(),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / f'release-evidence-{stamp}.json'
    latest_file = OUT_DIR / 'release-evidence-latest.json'

    out_file.write_text(json.dumps(bundle, indent=2) + '\n', encoding='utf-8')
    latest_file.write_text(json.dumps(bundle, indent=2) + '\n', encoding='utf-8')

    print(str(out_file))


if __name__ == '__main__':
    main()
