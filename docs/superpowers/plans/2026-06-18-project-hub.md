# Project Hub Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a standalone project hub app at `/home/aiagent/project-hub/` that serves as a master panel for all build project trackers across all servers, with auth, tracker linking, health checks, and SSH-based remote deployment.

**Architecture:** Python stdlib HTTPServer (no external dependencies) serving a vanilla HTML/JS SPA. Auth via session cookie. SSH deploy via `paramiko` (or stdlib `subprocess` calling system ssh). Tracker scaffold templates bundled as strings in server.py.

**Tech Stack:** Python 3 stdlib (http.server, json, uuid, hashlib, hmac, secrets, subprocess), vanilla HTML/CSS/JS, systemd.

---

### Task 1: Create project-hub directory and server with auth

**Files:**
- Create: `/home/aiagent/project-hub/server.py`
- Create: `/home/aiagent/project-hub/projects.json`
- Create: `/home/aiagent/project-hub/server-credentials.json`
- Create: `/home/aiagent/project-hub/users.json`

- [ ] **Step 1: Create directory and data files**

```bash
mkdir -p /home/aiagent/project-hub/templates/tracker
echo '{"projects":[]}' > /home/aiagent/project-hub/projects.json
echo '{"servers":[]}' > /home/aiagent/project-hub/server-credentials.json
echo '{"users":[{"username":"admin","password_hash":"","role":"admin"}]}' > /home/aiagent/project-hub/users.json
```

- [ ] **Step 2: Write server.py — core imports, config, data loading**

server.py will include:
- PORT from env or default 3010
- SESSION_SECRET from env or generated
- DATA_FILE, CRED_FILE, USERS_FILE paths
- load/save helpers for all JSON files
- `_make_id()`, `now()` helpers

- [ ] **Step 3: Write server.py — auth system**

- Login page handler (GET /login -> returns login HTML)
- Login POST handler (POST /login -> validate credentials, set session cookie)
- Logout handler
- Session validation decorator/check helper
- Password hashing with hashlib.sha256 + salt

- [ ] **Step 4: Write server.py — static file serving**

- Serve index.html for `/` and `/index.html`
- MIME type mapping for .html, .css, .js

- [ ] **Step 5: Write server.py — Projects REST API**

- GET /api/projects -> list with summary + tracker fields
- POST /api/projects -> create with all tracker fields
- GET /api/projects/{id} -> full project detail
- PATCH /api/projects/{id} -> update project fields
- DELETE /api/projects/{id} -> delete project

- [ ] **Step 6: Write server.py — Tasks sub-API**

- POST /api/projects/{id}/tasks -> add task
- PATCH /api/tasks/{id} -> update task
- DELETE /api/tasks/{id} -> delete task

- [ ] **Step 7: Write server.py — Health check endpoint**

- GET /api/projects/{id}/health -> HTTP GET to tracker_url, return {online: bool, status: int}
- GET /api/health/bulk -> ping all projects with tracker_url set, return statuses

- [ ] **Step 8: Write server.py — SSH + Deploy endpoints**

- POST /api/servers/test-ssh -> connect via SSH (subprocess or paramiko), return success/fail
- POST /api/projects/{id}/scaffold-tracker -> generate + deploy (local or SSH)
- POST /api/servers/credentials -> save server credentials (encrypt password with Fernet)
- GET /api/servers/credentials -> list saved servers (without secrets)

- [ ] **Step 9: Write server.py — SSE endpoint**

- GET /api/events/stream -> Server-Sent Events for live refresh

- [ ] **Step 10: Write server.py — main entry point**

- HTTPServer setup with (HOST, PORT)
- systemd notify or just print URL

- [ ] **Step 11: Commit**

```bash
git -C /home/aiagent/mission-control-ui add docs/superpowers/
git -C /home/aiagent/mission-control-ui commit -m "docs: add project-hub spec and plan"
```

### Task 2: Create the project hub UI (index.html)

**Files:**
- Create: `/home/aiagent/project-hub/index.html`

- [ ] **Step 1: Write the login page HTML**

- Full-screen login form with username/password
- Dark theme matching existing style
- POST to /login, redirect on success
- Inline CSS + JS, no external deps

- [ ] **Step 2: Write the project list view**

- Top bar with title "Project Hub", subtitle showing online count
- "New Project" button, "Refresh" button
- Grid of project cards, each showing:
  - Name, description
  - Health dot (green/amber/red) with status text
  - Folder path badge
  - Server + SSH user badge
  - Port badge
  - Task progress bar
  - "Open Tracker" button (if has_tracker)
  - "View Tasks" button (drill-down)
  - "Deploy Tracker" button (if no tracker)

- [ ] **Step 3: Write the project detail view**

- Back button to list
- Project header with name, description, tracker link
- Task management (table view + kanban toggle)
- Filter tabs (all, to do, in progress, blocked, review, done)
- Add task inline form
- Checkbox toggle for done
- Status dropdown inline
- Drag-and-drop kanban board
- CSV export

- [ ] **Step 4: Write the New Project modal**

- Segmented toggle: Local / Remote
- **Local tab fields:**
  - Project Name, Description
  - Local folder path (e.g., /home/aiagent/project/tracker)
  - Tracker port
  - "Create scaffold" checkbox, "Start service" checkbox
- **Remote tab fields:**
  - Project Name, Description
  - Server IP, SSH port, SSH username
  - Auth method (key/password), key path or password input
  - Remote folder path
  - Tracker port
  - "Test SSH Connection" button with result display
  - "Create scaffold" checkbox, "Start service" checkbox
- "Create Project" button

- [ ] **Step 5: Write the Deploy Tracker modal**

- For existing projects without a tracker
- Same fields as New Project but pre-filled from project data
- Deployment progress log (shows stdout from each step)
- "Test SSH" button

- [ ] **Step 6: Write the JavaScript API layer**

- `$(id)`, `esc(v)` helpers
- `loadList()` — fetch projects, render cards
- `loadProject(id)` — fetch one project, render detail
- `createProject(data)` — POST /api/projects
- `updateProject(id, data)` — PATCH /api/projects/{id}
- `deleteProject(id)` — DELETE /api/projects/{id}
- `testSSH(data)` — POST /api/servers/test-ssh
- `scaffoldTracker(id, data)` — POST /api/projects/{id}/scaffold-tracker
- `checkHealth(id)` — GET /api/projects/{id}/health
- SSE EventSource for live refresh
- Auto-refresh every 60s

- [ ] **Step 7: Write CSS styles**

- Dark theme using CSS custom properties
- Card grid layout
- Modal overlay styles
- Health dot styles (green/amber/red)
- Badge styles for server/folder/port info
- Responsive layout
- Existing styles from project-manager.html preserved

- [ ] **Step 8: Commit**

```bash
git -C /home/aiagent/project-hub init
git -C /home/aiagent/project-hub add .
git -C /home/aiagent/project-hub commit -m "feat: initial project hub app"
```

### Task 3: Create tracker scaffold templates

**Files:**
- Create: `/home/aiagent/project-hub/templates/tracker/server.py`
- Create: `/home/aiagent/project-hub/templates/tracker/index.html`
- Create: `/home/aiagent/project-hub/templates/tracker/data.json`
- Create: `/home/aiagent/project-hub/templates/tracker/tracker.service`

- [ ] **Step 1: Write tracker server.py template**

- Based on simplyclik-app/tracker/server.py
- PORT configurable via env var
- REST API: projects CRUD, tasks CRUD
- Static file serving for index.html
- SSE /api/events/stream
- CORS headers
- Data stored in data.json

- [ ] **Step 2: Write tracker index.html template**

- Dark theme matching project hub style
- Project list view with cards
- Per-project task table with status/priority/owner
- Filter tabs
- Checkbox toggle done
- Status inline dropdown
- CSV export
- SSE live refresh

- [ ] **Step 3: Write tracker data.json template**

```json
{"projects":[]}
```

- [ ] **Step 4: Write tracker.service template**

```ini
[Unit]
Description={project_name} Tracker
After=network.target

[Service]
Type=simple
User=aiagent
WorkingDirectory={folder_path}
ExecStart={python_path} {folder_path}/server.py
Restart=always
RestartSec=5
Environment=PORT={port}

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 5: Commit**

```bash
git -C /home/aiagent/project-hub add templates/
git -C /home/aiagent/project-hub commit -m "feat: add tracker scaffold templates"
```

### Task 4: Deploy and verify

**Files:**
- Create: `/home/aiagent/project-hub/project-hub.service`

- [ ] **Step 1: Create systemd service**

```ini
[Unit]
Description=Project Hub — Master Tracker Panel
After=network.target

[Service]
Type=simple
User=aiagent
WorkingDirectory=/home/aiagent/project-hub
ExecStart=/usr/bin/python3 /home/aiagent/project-hub/server.py
Restart=always
RestartSec=5
Environment=PORT=3010

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Install and start service**

```bash
sudo cp /home/aiagent/project-hub/project-hub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now project-hub.service
```

- [ ] **Step 3: Verify it's running**

```bash
curl -s http://localhost:3010/ | head -5
# Expected: <!DOCTYPE html> with login page
```

- [ ] **Step 4: Set default admin password**

```bash
# First run: user needs to set password
curl -s http://localhost:3010/
# Or create via API
```

- [ ] **Step 5: Commit**

```bash
git -C /home/aiagent/project-hub add project-hub.service
git -C /home/aiagent/project-hub commit -m "chore: add systemd service"
```
