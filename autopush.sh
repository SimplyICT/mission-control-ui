#!/bin/bash
REPO="$HOME/mission-control-repo"
LOG="$HOME/mission-control-repo/autopush.log"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting auto-push" >> "$LOG"

rsync -a --delete \
  --exclude='venv/' --exclude='__pycache__/' \
  --exclude='.env' --exclude='users.json' \
  --exclude='*.bak' --exclude='audit-reports/' \
  --exclude='generated_reports/' \
  "$HOME/mission-control-ui/" "$REPO/ui/"

rsync -a --delete \
  --exclude='venv/' --exclude='__pycache__/' \
  --exclude='.env' \
  "$HOME/mission-control-site/" "$REPO/site/"

cd "$REPO"
git add -A
if git diff --cached --quiet; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] No changes to push" >> "$LOG"
else
  git commit -m "Auto-backup $(date '+%Y-%m-%d %H:%M')"
  git push origin main
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Push complete" >> "$LOG"
fi