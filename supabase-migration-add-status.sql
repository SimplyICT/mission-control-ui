-- Run this in Supabase Dashboard SQL Editor
ALTER TABLE device_audits ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'in_progress';
