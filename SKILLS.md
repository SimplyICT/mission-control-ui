# Cybersecurity skill library (vendored)

The SOC ships with a curated view of a third-party cybersecurity skills library, so an
analyst (or the AI triage path) gets a named workflow instead of a generic prompt.

## Provenance

| | |
|---|---|
| Source | https://github.com/mukul975/Anthropic-Cybersecurity-Skills |
| Vendored copy | `/sdb-disk/dev/projects/cyber-skills` (read-only, pinned) |
| Pinned commit | `54a798831d2266a3ca61ce68a7acb80b81160d57` |
| Licence | Apache-2.0 — keep this file and the upstream `LICENSE` with any redistribution |
| Upstream size | 818 skills, 34 domains, 46 subdomains |
| Upstream CI | `validate-skills.yml` validates *structure*, not content correctness |

**Naming caveat:** despite the name, this is an independent community project — it is not
published by, or affiliated with, Anthropic PBC. It follows the agentskills.io convention,
which is also what this harness uses (`SKILL.md` + YAML frontmatter), so its layout is
directly compatible with our own skills.

The content spans offensive and defensive material. Treat it as reference material and
verify anything before acting on it; a skill describing a technique is not evidence that
the technique works as written in our environment.

## What we import, and what we deliberately do not

Offensive and dual-use skills are **excluded by default** (`offensive: true` in the index):

- whole domains: `red-teaming`, `penetration-testing`;
- per-skill patterns: `attacking-*`, `abusing-*`, `exploiting-*`, `bypassing-*`,
  C2/malleable-profile work, payloads, phishing simulation, credential dumping, password
  cracking, Kerberoasting, NTLM relay, exfiltration, post-exploitation, evasion, LOLBins.

Note this is decided **per skill, not per domain** — `identity-access-management` is
defensive, but `attacking-entra-id-with-roadtools` inside it is not. Current split:
**690 defensive imported, 128 offensive held back.**

The `include_offensive` flag on the API is the later switch for authorised work. It stays
`false` everywhere until that boundary is a deliberate decision with rules of engagement
attached — an autonomous path must never pick one of these up by accident.

## Two tiers

1. **Tier 1 — agent registry (`~/.omp/agent/skills/`, ~60 skills).** Symlinked from the
   vendored copy so the library stays authoritative. Bounded on purpose: the whole library
   is ~26k tokens of descriptions, which would be injected into every session and dilute
   skill selection. Tier 1 is the SOC lane's own subject matter (soc-operations,
   security-operations, incident-response, threat detection/hunting, endpoint, ransomware,
   phishing, forensics, identity).
2. **Everything defensive — SOC Playbooks library (690).** Indexed in `skill_index.json`,
   served on demand by `GET /api/skills*` and surfaced as "Analyst guidance" on findings,
   matched by MITRE technique. Never injected wholesale.

## Rebuilding / updating

```bash
git -C /sdb-disk/dev/projects/cyber-skills pull          # move to a newer upstream commit
python3 skills_index_build.py --link                     # rebuild index + relink tier 1
```
`skills_index_build.py` is the only tool: it parses each `SKILL.md` with a real YAML parser
(a hand-rolled one produced a skill literally named "Transfer of funds"), applies the
offensive filter, ranks the lane priority for tier 1, and records the vendored commit in
`skill_index.json` so the exact revision in use is auditable.

Environment overrides: `CYBER_SKILLS_SRC` (clone location), `SKILL_INDEX_OUT` (index path).
