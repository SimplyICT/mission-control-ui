BEGIN;

-- Per-centre colour (used as the accent on calendar entries / site rows)
ALTER TABLE sites ADD COLUMN IF NOT EXISTS audit_colour text;
UPDATE sites SET audit_colour = CASE site_name
         WHEN 'Benowa ELC'       THEN '#3B82F6'
         WHEN 'Benowa Hills ELC' THEN '#A855F7'
         WHEN 'Currumbin ELC'    THEN '#14B8A6'
         WHEN 'Riversdale ELC'   THEN '#EAB308'
         ELSE audit_colour END
 WHERE site_name IN ('Benowa ELC', 'Benowa Hills ELC', 'Currumbin ELC', 'Riversdale ELC');

-- Record the Riversdale field audit performed Tue 2026-09-08 (done on site, not entered in-app)
INSERT INTO device_audits (site_id, site_name, audit_date, auditor_name, audit_type,
                           summary_notes, status, report_generated)
SELECT s.site_id, s.site_name, DATE '2026-09-08', 'SimplyICT', 'Device Audit',
       'Recorded from field audit — not entered via the app', 'finalized', false
  FROM sites s
 WHERE s.site_name = 'Riversdale ELC'
   AND NOT EXISTS (
         SELECT 1 FROM device_audits a
          WHERE a.site_id = s.site_id AND a.audit_date = DATE '2026-09-08');

COMMIT;

SELECT site_name, audit_colour, audit_weekday, audit_frequency_months FROM sites ORDER BY site_name;
SELECT site_name, audit_date, status FROM device_audits
 WHERE site_name = 'Riversdale ELC' ORDER BY audit_date DESC LIMIT 3;
