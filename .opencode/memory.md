# Mission Control UI — Session Memory

2026-06-26: Fixed Mission Probe agent hardcoded URLs (audit.simplyict.com.au → mc.simplyict.com.au) in 7 files: install.ps1, install.sh, config.toml.example, app.py, help.html, site/help.html. Discovered Cloudflare Access on mc.simplyict.com.au blocks /monitoring-api/* — 78 probes offline. Probes need CF Access bypass rule or service tokens to connect.

2026-06-29 (session 11): Designed MC Launchpad upgrade — search bar + tag filter pills + favorites/pinned + collapsible sections for the 32-app landing page. Spec written at docs/superpowers/specs/2026-06-29-mc-launchpad-design.md. Waiting for user approval before implementation.
2026-06-29 (session 11): Implemented MC Launchpad — search bar (Ctrl+K, /, Escape), tag filter pills (Dashboard, Vault, Tool, App, Kanban, Link, SOC, Alerts, Admin, Bridge), favorites/pinned (localStorage), collapsible sections (localStorage). Single file change to index.html (250→434 lines). Awaiting user verification on live page.

2026-07-03: Added error handling to device-audit.html — loadSites/loadResumeAudits/initPage now catch fetch failures, show user-facing error message on status line, and log to console. Fixes silent empty site dropdown.
