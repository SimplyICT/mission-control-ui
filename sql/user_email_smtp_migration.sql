-- ═══════════════════════════════════════════════════════════════════
-- User email addresses + SMTP settings table
-- Run in Supabase SQL Editor:
--   https://supabase.com/dashboard/project/zhvxjuhgfudavxrfsasn/sql/new
-- Idempotent — safe to re-run. Restart device-audit-api afterwards.
-- ═══════════════════════════════════════════════════════════════════

-- 1. User notification email (admin-users → users, project task notifications)
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS email TEXT;

-- 2. Platform settings store (SMTP2Go config lives under key 'smtp')
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now()
);