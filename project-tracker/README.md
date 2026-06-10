# SimplyClik Project Tracker
This folder is the single source of truth for program-level progress.

## Files
- `tasks.json` canonical task data.
- `dashboard/index.html` read-only progress dashboard.
- `scripts/update-task-status.mjs` status update utility.

## Status values
- `not_started`
- `in_progress`
- `blocked`
- `review`
- `done` (requires at least one proof URL)

## Nested tasks
- Use `parent_id` on a task to make it a child of another task (for example `W1-02.1` with `parent_id: "W1-02"`).
- Parent and child tasks stay in the same `workstream`.
- The dashboard renders child tasks indented beneath their parent.

## Update task status
Run from repository root:
`node project-tracker/scripts/update-task-status.mjs --id W0-01 --status done --proof https://github.com/SimplyICT/SimplyClik/pull/8 --notes "Tracker schema merged"`

Optional flags:
- `--owner <name>`
- `--target_date <YYYY-MM-DD>`
- `--proof <url1,url2,...>`
- `--notes "free text"`

## View dashboard locally
Run from repository root:
`python -m http.server 8080`

Open:
`http://localhost:8080/project-tracker/dashboard/`

The dashboard auto-refreshes every 15 seconds.

## Deploy to existing server
Copy tracker files to the web root served by your existing audit host:
`scp -r project-tracker/* <user>@208.87.135.84:/var/www/audit-system/project-tracker/`

Then browse:
`https://<your-domain>/project-tracker/dashboard/`

If your web root path differs, use the equivalent destination directory currently hosting the audit UI.
