# Project Hub — Master Tracker Panel

## Goal

Extend the existing `project-manager.html` page to become a master hub for all build project trackers across all servers. Each project card gains tracker link, server metadata, health status, and deploy actions. New projects can be created with an optional tracker scaffold deployed locally or via SSH.

## Existing Infrastructure

- **Server:** 208.87.135.84 (mission-control-ui), Python FastAPI on port 8095
- **Backend:** `app.py` — serves HTML pages, REST API for projects/tasks
- **Data:** `projects.json` — stores projects with tasks
- **Frontend:** `project-manager.html` — vanilla JS, dark theme, kanban + list view
- **Existing trackers:**
  - SimplyClik: 208.87.135.84:3003 (standalone Python HTTPServer)
  - PaintCo: 208.87.135.183:3004 (different server)
  - Mission Control Site: 208.87.135.84:8097 (monitoring dashboards)

## Data Model Changes

### projects.json — new fields per project

```json
{
  "id": "abc123",
  "name": "SimplyClik App",
  "description": "Backend migration program",
  "tracker_url": "http://208.87.135.84:3003",
  "server_host": "208.87.135.84",
  "server_port": 3003,
  "ssh_user": "aiagent",
  "ssh_auth_method": "key",
  "ssh_key_path": "/home/aiagent/.ssh/id_rsa",
  "folder_path": "/home/aiagent/simplyclik-app/tracker",
  "has_tracker": true,
  "tracker_port": 3003,
  "created_at": "2026-06-05T00:00:00+00:00",
  "updated_at": "2026-06-10T10:00:00+00:00",
  "tasks": [...]
}
```

### server-credentials.json — new file (chmod 600)

Stored separately from projects, keyed by host. Passwords are encrypted using Fernet. SSH keys are referenced by path only.

Note: projects.json stores SSH metadata for redeployment reference (user, key path). Actual secrets (passwords) live only in server-credentials.json.

```json
{
  "servers": [
    {
      "host": "208.87.135.183",
      "port": 22,
      "username": "aiagent",
      "auth_method": "key",
      "key_path": "/home/aiagent/.ssh/id_rsa",
      "last_used": "2026-06-18T..."
    }
  ]
}
```

For password auth, the password is encrypted using `cryptography.fernet` with a key derived from the app's secret key.

## UI Changes (project-manager.html)

### List View — Project Cards

Each card shows:
- Project name + description
- Health status dot (green/amber/red) — based on pinging tracker_url
- Folder path badge
- Server + SSH user badge
- Tracker port badge
- Task progress bar (existing, kept)
- **Open Tracker** button (if has_tracker) — links to tracker_url
- **Tasks** button — existing drill-down to kanban/list view
- **Deploy Tracker** button (if !has_tracker) — opens deploy modal

### New Project Modal — Toggle Between Local / Remote

A single modal with a segmented toggle:

**🏠 Local tab:**
- Project Name, Description
- Local folder path
- Tracker port
- Auto-fill tracker_url from current server IP + port

**☁️ Remote tab:**
- Project Name, Description
- Server IP, SSH Port, SSH Username
- Auth method (key/password), key path or password
- Remote folder path
- Tracker port
- Test SSH Connection button

Both tabs: "Create tracker scaffold" checkbox + "Start service" checkbox.

### Deploy Tracker Modal

For existing projects without a tracker. Same fields as New Project modal but pre-fills from stored server credentials if available. Shows deployment progress log in the modal.

## Backend API Changes (app.py)

### Modified endpoints

| Method | Endpoint | Change |
|--------|----------|--------|
| POST | /api/projects | Accept tracker_url, server_host, server_port, ssh_user, ssh_auth_method, ssh_key_path, folder_path, has_tracker, tracker_port |
| PATCH | /api/projects/{id} | Accept same fields (reuse PATCH for project update) |
| GET | /api/projects | Return tracker fields in summary |
| GET | /api/projects/{id} | Return full project with tracker fields |

### New endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /api/projects/{id}/scaffold-tracker | Generate tracker files + deploy (local or SSH) |
| GET | /api/projects/{id}/health | Ping tracker URL, return {online: bool, status_code: int} |
| POST | /api/servers/test-ssh | Test SSH connection with given credentials |
| GET | /api/servers/credentials | List saved server credentials |
| POST | /api/servers/credentials | Save server credentials |

### Scaffold Tracker Flow

1. Generate 4 files from templates:
   - `index.html` — tracker UI (clone of simplyclik tracker style)
   - `server.py` — standalone Python HTTPServer (stdlib, no deps)
   - `data.json` — empty projects structure
   - `tracker.service` — systemd unit file
2. If local: write files to folder_path, install systemd service, start it
3. If remote: write files to temp, SCP to remote, SSH install + start
4. Ping tracker_url to verify
5. Update project: has_tracker=true, tracker_url set
6. Return deployment log as response

## Tracker Scaffold Template

### server.py

Standalone Python HTTP server serving tracker UI + REST API. Based on the existing simplyclik tracker at `/home/aiagent/simplyclik-app/tracker/server.py`:
- Port configurable via env var or command arg
- Serves index.html as static file
- REST API: /api/projects (GET/POST), /api/projects/{id} (GET/PATCH/DELETE), /api/projects/{id}/tasks (POST), /api/tasks/{id} (PATCH/DELETE)
- SSE /api/events/stream for live updates
- CORS headers for cross-origin access
- Data persisted to data.json

### index.html

Tracker UI matching the existing dark theme. Shows:
- Project list with cards
- Per-project task table with status/priority/owner
- CSV export
- SSE live refresh

## Security

- SSH passwords encrypted with Fernet (symmetric) using app secret key
- SSH keys referenced by path only, never stored in DB
- Server credentials endpoint requires admin role
- Test SSH only opens connection, performs no destructive operations
- Tracker scaffold validates folder_path to prevent path traversal

## Future Considerations

- SSH key management UI (upload keys)
- Bulk health check across all project trackers
- Automatic re-deploy on tracker version update
- Webhook notifications when tracker goes offline
