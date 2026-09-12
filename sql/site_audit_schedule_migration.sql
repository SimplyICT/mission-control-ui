BEGIN;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS audit_schedule_enabled boolean DEFAULT true;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS audit_weekday smallint;                -- 0=Mon .. 6=Sun
ALTER TABLE sites ADD COLUMN IF NOT EXISTS audit_frequency_months integer DEFAULT 1;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS next_audit_override date;

UPDATE sites SET audit_weekday = 5, audit_frequency_months = 1
 WHERE site_name IN ('Benowa ELC', 'Benowa Hills ELC', 'Riversdale ELC');
UPDATE sites SET audit_weekday = 1, audit_frequency_months = 1
 WHERE site_name = 'Currumbin ELC';
COMMIT;

SELECT site_name, audit_schedule_enabled AS enabled, audit_weekday AS wd, audit_frequency_months AS freq_m
  FROM sites ORDER BY site_name;
