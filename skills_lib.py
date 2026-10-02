"""Access to the vendored cybersecurity skill library (SOC Playbooks).

The heavy index (`skill_index.json`) is built by skills_index_build.py from the pinned
clone at SKILLS_SRC. This module only reads it: search/match return bounded, defensive
records by default (`include_offensive` is reserved for a later, explicit opt-in), and
`get` attaches the SKILL.md body on demand so the list stays cheap.

Nothing here may raise into a request path: every file/YAML/JSON access is guarded and
degrades to an empty result.
"""
import json
import os
import re
from pathlib import Path

INDEX_PATH = Path(os.environ.get("SKILL_INDEX_PATH")
                  or (Path(__file__).resolve().parent / "skill_index.json"))
SKILLS_SRC = Path(os.environ.get("CYBER_SKILLS_SRC", "/sdb-disk/dev/projects/cyber-skills"))
BODY_LIMIT = 20000
SEARCH_MAX = 200  # hard ceiling: a caller cannot pull the whole 818-record index
MATCH_MAX = 50

# detection_type -> the subdomain whose playbooks fit it, worth a small ranking bonus.
# Domains whose skills describe something an analyst does next (triage, hunt, respond,
# collect evidence). Used as a ranking bonus, not a filter.
ACTION_SUBDOMAINS = {
    "incident-response", "soc-operations", "security-operations", "threat-hunting",
    "threat-detection", "digital-forensics", "malware-analysis", "endpoint-security",
    "ransomware-defense", "vulnerability-management",
}

_DETECTION_SUBDOMAINS = {
    "defender_alert": "endpoint-security",
    "defender_incident": "incident-response",
    "mde_alert": "endpoint-security",
    "endpoint": "endpoint-security",
    "mfa_fatigue": "identity-access-management",
    "impossible_travel": "identity-access-management",
    "anonymous_ip": "identity-access-management",
    "privileged_role": "identity-access-management",
    "mail_forwarding": "identity-access-management",
    "entra_risk": "identity-access-management",
    "oauth_consent": "identity-access-management",
    "security_info_reset": "identity-access-management",
    "account_status_change": "identity-access-management",
}

_CACHE = {"mtime": None, "index": {}}


def load_index() -> dict:
    """Read skill_index.json, cached by mtime. Missing/unreadable -> {} (never raises)."""
    try:
        mtime = INDEX_PATH.stat().st_mtime_ns
    except OSError:
        return {}
    if _CACHE["mtime"] == mtime and _CACHE["index"]:
        return _CACHE["index"]
    try:
        data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    _CACHE["mtime"] = mtime
    _CACHE["index"] = data
    return data


def counts() -> dict:
    """Index counts plus provenance, for headers/health badges."""
    idx = load_index()
    out = dict(idx.get("counts") or {})
    out["built_at"] = idx.get("built_at", "")
    out["vendored_commit"] = idx.get("vendored_commit", "")
    return out


def _public_record(s: dict) -> dict:
    return {
        "name": s.get("name", ""),
        "subdomain": s.get("subdomain", ""),
        "tags": list(s.get("tags") or []),
        "mitre_attack": list(s.get("mitre_attack") or []),
        "nist_csf": list(s.get("nist_csf") or []),
        "description": s.get("description", ""),
        "license": s.get("license", ""),
        "path": s.get("path", ""),
        "offensive": bool(s.get("offensive")),
    }


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 2]


def _token_in(tok: str, s: dict) -> bool:
    return (tok in str(s.get("name", "")).lower()
            or any(tok in str(t).lower() for t in (s.get("tags") or []))
            or tok in str(s.get("description", "")).lower())


def _token_hits(tokens: list[str], s: dict) -> int:
    return sum(1 for tok in tokens if _token_in(tok, s))


def _tech_hit(qid: str, skill_techs) -> bool:
    return _technique_score(qid, skill_techs)[0] > 0


def _technique_score(qid: str, skill_techs) -> tuple[int, str]:
    """Exact id (5) beats a parent/child id, e.g. T1003 vs T1003.001 (3)."""
    best, why = 0, ""
    for raw in skill_techs or []:
        tid = str(raw).strip().upper()
        if not tid:
            continue
        if tid == qid:
            return 5, qid
        if tid.startswith(qid + ".") or qid.startswith(tid + "."):
            if best < 3:
                best, why = 3, f"{qid} (~{tid})"
    return best, why


def _as_techniques(value) -> list[str]:
    """Accept None, a comma string, or a list/tuple of ids."""
    if not value:
        return []
    if isinstance(value, str):
        parts = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        parts = list(value)
    else:
        return []
    out = []
    for p in parts:
        tid = str(p).strip().upper()
        if tid and tid not in out:
            out.append(tid)
    return out


def _query_why(tokens: list[str], s: dict) -> str:
    for tok in tokens:
        for tag in s.get("tags") or []:
            if tok in str(tag).lower():
                return f"tag: {tag}"
    for tok in tokens:
        if tok in str(s.get("name", "")).lower():
            return f"name: {tok}"
    return f"text: {tokens[0]}"


def search(q="", subdomain="", technique="", limit=50, include_offensive=False) -> list[dict]:
    """Filter the index by free text, subdomain, and/or technique. Newest index wins.

    Ranking is relevance-by-token when `q` is given, otherwise alphabetical, so the UI
    gets a stable order without us shipping a scorer for a browse list.
    """
    idx = load_index()
    ql = str(q or "").strip()
    tokens = _tokens(ql)
    sub = str(subdomain or "").strip().lower()
    tech = str(technique or "").strip().upper()
    out = []
    for s in idx.get("skills") or []:
        if s.get("offensive") and not include_offensive:
            continue
        if sub and sub not in str(s.get("subdomain", "")).lower():
            continue
        if tech and not _tech_hit(tech, s.get("mitre_attack")):
            continue
        if tokens and not any(_token_in(tok, s) for tok in tokens):
            continue
        out.append(_public_record(s))
    if tokens:
        out.sort(key=lambda r: (-_token_hits(tokens, r), r["name"]))
    else:
        out.sort(key=lambda r: r["name"])
    try:
        cap = max(0, min(int(limit), SEARCH_MAX))
    except (TypeError, ValueError):
        cap = 50
    return out[:cap]


def match(techniques=None, detection_type="", q="", limit=3, include_offensive=False) -> list[dict]:
    """Rank skills against event/case signals: technique ids, free text, detection type.

    Score: exact technique 5, parent/child technique 3, each q-token overlap 1 (cap 3),
    matching detection-type subdomain 1. `why` names the strongest reason so a triage
    panel can show why a playbook was suggested.
    """
    idx = load_index()
    techs = _as_techniques(techniques)
    tokens = _tokens(str(q or "").strip())
    dtype = str(detection_type or "").strip().lower()
    sub_bonus = _DETECTION_SUBDOMAINS.get(dtype)
    hits = []
    for s in idx.get("skills") or []:
        if s.get("offensive") and not include_offensive:
            continue
        candidates = []
        score = 0
        for tid in techs:
            ts, tw = _technique_score(tid, s.get("mitre_attack"))
            if ts:
                score += ts
                candidates.append((ts, tw))
        q_hits = [tok for tok in tokens if _token_in(tok, s)]
        if q_hits:
            score += min(len(q_hits), 3)
            candidates.append((1, _query_why(q_hits, s)))
        if sub_bonus and str(s.get("subdomain", "")) == sub_bonus:
            score += 1
            candidates.append((1, f"subdomain: {sub_bonus}"))
        # A technique tag alone does not make a skill the right *next step*: a T1003.001
        # alert matched "deploying-edr-agent-with-crowdstrike" first, purely on alphabetical
        # tie-break, ahead of the credential-dump playbooks. Weight the analyst-response
        # domains so the suggestion is actionable rather than merely related.
        if str(s.get("subdomain", "")) in ACTION_SUBDOMAINS:
            score += 2
            candidates.append((2, f"subdomain: {s.get('subdomain')}"))
        if not candidates:
            continue
        rec = _public_record(s)
        rec["score"] = score
        rec["why"] = max(candidates, key=lambda c: c[0])[1]
        hits.append(rec)
    hits.sort(key=lambda r: (-r["score"], r["name"]))
    try:
        cap = max(0, min(int(limit), MATCH_MAX))
    except (TypeError, ValueError):
        cap = 3
    return hits[:cap]


def _read_body(rel: str):
    if not rel:
        return None
    p = Path(str(rel))
    if not p.is_absolute():
        p = SKILLS_SRC.parent / p
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:BODY_LIMIT]
    except Exception:
        return None


def get(name) -> dict | None:
    """Index record plus SKILL.md body. Offensive skills stay out (no opt-in flag here)."""
    idx = load_index()
    rec = next((s for s in idx.get("skills") or [] if s.get("name") == name), None)
    if rec is None or rec.get("offensive"):
        return None
    out = _public_record(rec)
    out["body"] = _read_body(rec.get("path", ""))
    return out
