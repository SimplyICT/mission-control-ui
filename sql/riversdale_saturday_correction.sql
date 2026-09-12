-- Riversdale is a Saturday-only audit centre: move the field-audit record off
-- Tuesday 8 Sep 2026 to the Saturday of that cycle (Sat 5 Sep 2026).
UPDATE device_audits a
   SET audit_date = DATE '2026-09-05',
       summary_notes = 'Recorded from field audit (corrected to Saturday per audit schedule)'
  FROM sites s
 WHERE s.site_id = a.site_id
   AND s.site_name = 'Riversdale ELC'
   AND a.audit_date = DATE '2026-09-08';

SELECT s.site_name, a.audit_date, to_char(a.audit_date, 'Dy') AS day_name, a.status, a.summary_notes
  FROM device_audits a JOIN sites s ON s.site_id = a.site_id
 WHERE s.site_name = 'Riversdale ELC'
 ORDER BY a.audit_date DESC LIMIT 3;
