#!/usr/bin/env python3
"""Build the SOC's skill index from the vendored cybersecurity skills library.

Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills (Apache-2.0).
Community project, not affiliated with Anthropic - the name follows Anthropic's Agent
Skills convention, which is also what this harness uses (`SKILL.md` + YAML frontmatter).

Vendored, pinned, read-only at SKILLS_SRC. Run this after updating the clone; the output
is what the SOC serves and what the agent registry links.

    python3 skills_index_build.py            # rebuild skill_index.json
    python3 skills_index_build.py --tier1    # also print the bounded agent-registry set

Two tiers on purpose:
  * tier 1 (agent registry, ~60 skills) - injected into an agent session, so it is kept
    small; the whole library would cost ~26k tokens per session and dilute skill choice.
  * everything defensive (the library) - indexed for the SOC's Playbooks page, loaded on
    demand by technique or search, never injected wholesale.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SKILLS_SRC = Path(os.environ.get("CYBER_SKILLS_SRC", "/sdb-disk/dev/projects/cyber-skills"))
OUT = Path(os.environ.get("SKILL_INDEX_OUT", Path(__file__).resolve().parent / "skill_index.json"))

# Offensive / dual-use content stays out of anything an autonomous path can reach
# ("defensive now, offensive later behind a flag"). Matched per skill, not per domain:
# e.g. identity-access-management is defensive but "attacking-entra-id-with-roadtools" is not.
OFFENSIVE_DOMAINS = {"red-teaming", "penetration-testing"}
OFFENSIVE_PATTERNS = (
    r"^attacking-", r"^abusing-", r"^exploiting-", r"^bypassing-", r"-c2-", r"command-and-control",
    r"payload", r"phishing-simulation", r"credential-dump", r"password-cracking", r"hashcat",
    r"kerberoast", r"relay", r"privilege-escalation-with", r"adversary-in-the-browser",
    r"initial-access", r"exfiltrat", r"post-exploitation", r"evasion", r"living-off-the-land-binaries",
)

# Lane priority: what this SOC actually does, most first. Used only to pick tier 1.
LANE_PRIORITY = [
    "soc-operations", "security-operations", "incident-response", "threat-detection",
    "threat-hunting", "endpoint-security", "ransomware-defense", "phishing-defense",
    "digital-forensics", "malware-analysis", "identity-access-management",
    "vulnerability-management", "threat-intelligence", "network-security",
    "cloud-security", "compliance-governance", "zero-trust-architecture",
]
TIER1_LIMIT = 60


def frontmatter(path: Path) -> dict:
    """Parse the YAML frontmatter with a real YAML parser.

    Hand-rolled key:value scanning gets fooled by descriptions that contain YAML examples
    (one skill's description yielded a skill named "Transfer of funds"). PyYAML handles
    block scalars and lists correctly.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")[:10000]
    m = re.match(r"^---\n(.*?)\n---", raw, re.S)
    if not m:
        return {}
    try:
        import yaml
        data = yaml.safe_load(m.group(1))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def as_list(value) -> list:
    return value if isinstance(value, list) else ([value] if value else [])


def is_offensive(name: str, subdomain: str, tags: list) -> bool:
    if subdomain in OFFENSIVE_DOMAINS:
        return True
    blob = f"{name} {' '.join(tags)}".lower()
    return any(re.search(p, blob) for p in OFFENSIVE_PATTERNS)


def build() -> dict:
    if not (SKILLS_SRC / "skills").is_dir():
        sys.exit(f"skill source missing: {SKILLS_SRC}/skills (clone the repo there first)")
    commit = ""
    try:
        import subprocess
        commit = subprocess.run(["git", "-C", str(SKILLS_SRC), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        pass

    skills = []
    for path in sorted((SKILLS_SRC / "skills").glob("*/SKILL.md")):
        fm = frontmatter(path)
        name = str(fm.get("name") or path.parent.name)
        subdomain = str(fm.get("subdomain") or "").strip()
        tags = [str(t) for t in as_list(fm.get("tags"))]
        offensive = is_offensive(name, subdomain, tags)
        skills.append({
            "name": name,
            "subdomain": subdomain,
            "tags": tags,
            "mitre_attack": [str(t) for t in as_list(fm.get("mitre_attack"))],
            "nist_csf": [str(t) for t in as_list(fm.get("nist_csf"))],
            "description": re.sub(r"\s+", " ", str(fm.get("description") or ""))[:600],
            "license": str(fm.get("license") or "Apache-2.0"),
            "path": str(path.relative_to(SKILLS_SRC.parent)),
            "offensive": offensive,
        })

    ranked = sorted(
        [s for s in skills if not s["offensive"]],
        key=lambda s: (LANE_PRIORITY.index(s["subdomain"]) if s["subdomain"] in LANE_PRIORITY else 99,
                       -len(s["mitre_attack"]), s["name"]),
    )
    tier1 = [s["name"] for s in ranked[:TIER1_LIMIT]]
    return {
        "source": "https://github.com/mukul975/Anthropic-Cybersecurity-Skills",
        "license": "Apache-2.0",
        "note": "Community project, not affiliated with Anthropic. Structure validated by its CI; "
                "content is reference material - verify before acting.",
        "vendored_commit": commit,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "counts": {"total": len(skills),
                   "defensive": sum(1 for s in skills if not s["offensive"]),
                   "offensive_excluded": sum(1 for s in skills if s["offensive"])},
        "tier1": tier1,
        "lane_priority": LANE_PRIORITY,
        "skills": skills,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier1", action="store_true", help="print the tier-1 names and exit")
    ap.add_argument("--link", action="store_true",
                    help="(re)link the tier-1 skills into ~/.omp/agent/skills for agent use")
    args = ap.parse_args()
    index = build()
    if args.link:
        import shutil
        dest = Path.home() / ".omp/agent/skills"
        dest.mkdir(parents=True, exist_ok=True)
        linked = 0
        for name in index["tier1"]:
            rel = next((s["path"] for s in index["skills"] if s["name"] == name), "")
            target = (SKILLS_SRC.parent / rel).parent
            if not target.is_dir():
                continue
            link = dest / name
            if link.is_symlink() or link.exists():
                if link.is_dir() and not link.is_symlink():
                    shutil.rmtree(link)
                else:
                    link.unlink()
            link.symlink_to(target)
            linked += 1
        removed = [d for d in dest.iterdir()
                   if d.is_symlink() and str(d.resolve()).startswith(str(SKILLS_SRC))
                   and d.name not in index["tier1"]]
        for d in removed:
            d.unlink()
        print(f"linked {linked} tier-1 skills into {dest} (pruned {len(removed)})")
    if args.tier1:
        print("\n".join(index["tier1"]))
        return 0
    OUT.write_text(json.dumps(index, indent=1))
    c = index["counts"]
    print(f"wrote {OUT} | total {c['total']} | defensive {c['defensive']} | "
          f"offensive excluded {c['offensive_excluded']} | tier1 {len(index['tier1'])}")
    print(f"vendored commit: {index['vendored_commit'][:12] or 'unknown'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
