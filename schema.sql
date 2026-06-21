-- ================================================================
-- Mission Control — Complete Supabase Schema
-- Project: zhvxjuhgfudavxrfsasn.supabase.co
-- Generated from live OpenAPI spec: 2026-06-03
--
-- Usage: paste into Supabase SQL Editor and run.
-- Tables are created with IF NOT EXISTS — safe to re-run.
-- ================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ================================================================
-- GROUP: ACECQA Compliance
-- ================================================================

-- ── sites ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.sites (
  site_id                                  uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_name                                text  NOT NULL,
  company_name                             text,
  location                                 text,
  created_at timestamp with time zone DEFAULT now(),
  address                                  text,
  contact_name                             text,
  contact_email                            text,
  contact_phone                            text,
  notes                                    text,
  active                                   boolean,
  sharepoint_tenant_id                     text,
  sharepoint_client_id                     text,
  sharepoint_client_secret                 text,
  sharepoint_site_url                      text,
  sharepoint_drive_id                      text,
  sharepoint_folder                        text,
  sharepoint_enabled                       boolean,
  photo_retention_days                     integer DEFAULT 31,
  photo_count_threshold                    integer DEFAULT 1000,
  approved_storage                         text,
  personal_cloud_permitted                 boolean,
  audit_frequency_days                     integer DEFAULT 90,
  last_policy_review_date                  date,
  policy_document_url                      text,
  digital_tech_policy                      boolean,
  photo_video_policy                       boolean,
  staff_acceptable_use                     boolean,
  families_informed                        boolean,
  annual_review_current                    boolean,
  consent_forms_current                    boolean,
  photo_policy_documented                  boolean,
  staff_training_current                   boolean,
  encryption_enforced                      boolean,
  access_controls_documented               boolean,
  data_retention_policy                    boolean,
  incident_response_plan                   boolean,
  privacy_impact_assessment                boolean,
  third_party_data_agreement               boolean
);

ALTER TABLE public.sites ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_sites" ON public.sites
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── devices ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.devices (
  serial_number                            text  NOT NULL,
  device_type                              text,
  brand_model                              text,
  date_of_purchase                         date,
  assigned_user_room                       text,
  intended_use                             text,
  connectivity                             text,
  recording_storage_capabilities           text,
  created_at timestamp with time zone DEFAULT now(),
  device_id                                uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid,
  asset_tag                                text,
  device_name                              text,
  assigned_room                            text,
  assigned_user                            text,
  mac_address_wifi                         text,
  mac_address_lan                          text,
  ip_address                               text,
  processor                                text,
  ram                                      text,
  storage                                  text,
  operating_system                         text,
  os_version                               text,
  warranty_expiry                          date,
  status                                   text,
  notes                                    text,
  updated_at timestamp with time zone DEFAULT now(),
  is_active                                boolean DEFAULT true
);

ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_devices" ON public.devices
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── device_audits ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.device_audits (
  audit_batch_id                           uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid,
  site_name                                text,
  audit_date                               date  NOT NULL,
  auditor_name                             text,
  audit_type                               text,
  summary_notes                            text,
  total_devices                            integer,
  devices_audited                          integer,
  devices_missing                          integer,
  critical_findings                        integer,
  report_generated                         boolean DEFAULT false,
  report_url                               text,
  created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.device_audits ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_device_audits" ON public.device_audits
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── audit_entries ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.audit_entries (
  audit_id                                 uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  serial_number                            text,
  audit_date                               text,
  security_settings_applied                text,
  onedrive_status                          text,
  windows_updates                          text,
  security_check                           text,
  windows_os                               text,
  ios_version                              text,
  update_status                            text,
  camera_sync_off                          boolean,
  onedrive_sync_on                         boolean,
  photos_count                             integer,
  photos_date                              date,
  total_photos                             integer,
  ignore_flag                              boolean DEFAULT false,
  notes                                    text,
  site_name                                text,
  assigned_user_room                       text,
  audit_batch_id                           uuid,
  device_id                                uuid,
  device_present                           boolean,
  device_name                              text,
  device_type                              text,
  assigned_user                            text,
  assigned_room                            text,
  os_version                               text,
  ip_address                               text,
  mac_address_wifi                         text,
  mac_address_lan                          text,
  password_issue                           boolean,
  weak_pin_detected                        boolean,
  security_breach                          boolean,
  breach_notes                             text,
  recommended_action                       text,
  created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.audit_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_audit_entries" ON public.audit_entries
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── remediation_actions ────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.remediation_actions (
  action_id                                uuid  NOT NULL,
  site_id                                  text  NOT NULL,
  audit_batch_id                           text,
  source                                   text  NOT NULL,
  finding_type                             text  NOT NULL,
  device_serial                            text,
  description                              text  NOT NULL,
  assigned_to                              text,
  priority                                 text  NOT NULL,
  status                                   text  NOT NULL,
  due_date                                 date,
  resolved_date                            date,
  resolution_notes                         text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.remediation_actions ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_remediation_actions" ON public.remediation_actions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── incidents ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.incidents (
  incident_id                              uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  text  NOT NULL,
  incident_date                            date  NOT NULL,
  reported_by                              text,
  incident_type                            text  NOT NULL,
  severity                                 text  NOT NULL,
  description                              text  NOT NULL,
  children_affected                        boolean DEFAULT false,
  affected_count                           integer,
  mandatory_reportable                     boolean DEFAULT false,
  reported_to                              text,
  reported_date                            date,
  response_actions                         text,
  status                                   text  NOT NULL,
  resolved_date                            date,
  resolution_notes                         text,
  linked_audit_batch_id                    text,
  linked_device_serial                     text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_incidents" ON public.incidents
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ================================================================
-- GROUP: Network Monitoring
-- ================================================================

-- ── mc_sites ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_sites (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_code                                text  NOT NULL,
  site_name                                text  NOT NULL,
  description                              text,
  timezone                                 text,
  is_active                                boolean DEFAULT true  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_sites ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_sites" ON public.mc_sites
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_probe_agents ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_probe_agents (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  agent_key                                text  NOT NULL,
  agent_name                               text  NOT NULL,
  hostname                                 text,
  os_name                                  text,
  os_version                               text,
  agent_version                            text,
  lan_ip                                   text,
  wan_ip                                   text,
  status                                   text  NOT NULL,
  last_seen_at timestamp with time zone DEFAULT now(),
  last_heartbeat_at timestamp with time zone DEFAULT now(),
  metadata                                 text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_probe_agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_probe_agents" ON public.mc_probe_agents
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_probe_heartbeats ────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_probe_heartbeats (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  agent_id                                 uuid  NOT NULL,
  heartbeat_at timestamp with time zone DEFAULT now()  NOT NULL,
  status                                   text  NOT NULL,
  lan_ip                                   text,
  wan_ip                                   text,
  cpu_percent                              numeric,
  memory_percent                           numeric,
  disk_percent                             numeric,
  uptime_seconds                           integer,
  payload                                  text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_probe_heartbeats ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_probe_heartbeats" ON public.mc_probe_heartbeats
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_network_devices ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_network_devices (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  first_seen_by_agent_id                   uuid,
  last_seen_by_agent_id                    uuid,
  ip_address                               text,
  mac_address                              text,
  hostname                                 text,
  vendor                                   text,
  device_type                              text,
  friendly_name                            text,
  criticality                              text  NOT NULL,
  expected_online                          boolean  NOT NULL,
  status                                   text  NOT NULL,
  last_seen_at timestamp with time zone DEFAULT now(),
  last_online_at timestamp with time zone DEFAULT now(),
  last_offline_at timestamp with time zone DEFAULT now(),
  last_latency_ms                          numeric,
  notes                                    text,
  tags                                     jsonb  NOT NULL,
  metadata                                 text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_network_devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_network_devices" ON public.mc_network_devices
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_device_observations ─────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_device_observations (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  agent_id                                 uuid,
  device_id                                uuid,
  observed_at timestamp with time zone DEFAULT now()  NOT NULL,
  ip_address                               text,
  mac_address                              text,
  hostname                                 text,
  status                                   text  NOT NULL,
  latency_ms                               numeric,
  packet_loss_percent                      numeric,
  method                                   text,
  raw                                      text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_device_observations ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_device_observations" ON public.mc_device_observations
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_network_metrics ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_network_metrics (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  agent_id                                 uuid,
  measured_at timestamp with time zone DEFAULT now()  NOT NULL,
  metric_type                              text  NOT NULL,
  target                                   text,
  value                                    numeric,
  unit                                     text,
  status                                   text  NOT NULL,
  details                                  text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_network_metrics ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_network_metrics" ON public.mc_network_metrics
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_alerts ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_alerts (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  agent_id                                 uuid,
  device_id                                uuid,
  alert_type                               text  NOT NULL,
  severity                                 text  NOT NULL,
  status                                   text  NOT NULL,
  title                                    text  NOT NULL,
  message                                  text,
  source                                   text  NOT NULL,
  first_seen_at timestamp with time zone DEFAULT now()  NOT NULL,
  last_seen_at timestamp with time zone DEFAULT now()  NOT NULL,
  acknowledged_at timestamp with time zone DEFAULT now(),
  acknowledged_by                          text,
  resolved_at timestamp with time zone DEFAULT now(),
  resolved_by                              text,
  count                                    integer  NOT NULL,
  fingerprint                              text,
  metadata                                 text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_alerts" ON public.mc_alerts
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_incidents ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_incidents (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  site_id                                  uuid  NOT NULL,
  severity                                 text  NOT NULL,
  status                                   text  NOT NULL,
  title                                    text  NOT NULL,
  summary                                  text,
  opened_at timestamp with time zone DEFAULT now()  NOT NULL,
  acknowledged_at timestamp with time zone DEFAULT now(),
  resolved_at timestamp with time zone DEFAULT now(),
  owner                                    text,
  metadata                                 text  NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_incidents" ON public.mc_incidents
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_incident_alerts ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_incident_alerts (
  incident_id                              uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  alert_id                                 uuid  NOT NULL,
  linked_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_incident_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_incident_alerts" ON public.mc_incident_alerts
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_agent_releases ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_agent_releases (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  version                                  text  NOT NULL,
  file_path                                text  NOT NULL,
  checksum_sha256                          text,
  changelog                                text,
  is_current                               boolean DEFAULT false,
  is_critical                              boolean DEFAULT false,
  file_size_bytes                          bigint,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_agent_releases ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_agent_releases" ON public.mc_agent_releases
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_device_patterns ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_device_patterns (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  device_id                                uuid  NOT NULL REFERENCES public.mc_network_devices(id) ON DELETE CASCADE,
  offline_count_30d                        integer DEFAULT 0,
  total_offline_events                     integer DEFAULT 0,
  first_seen_at timestamp with time zone DEFAULT now(),
  last_seen_at timestamp with time zone DEFAULT now(),
  last_offline_at timestamp with time zone,
  offline_events                           jsonb DEFAULT '[]'::jsonb NOT NULL,
  online_events                            jsonb DEFAULT '[]'::jsonb NOT NULL,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_device_patterns ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_device_patterns" ON public.mc_device_patterns
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_audit_device_links ──────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mc_audit_device_links (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  mc_device_id                             uuid  NOT NULL,
  audit_serial_number                      text,
  audit_device_id                          text,
  confidence                               text  NOT NULL,
  notes                                    text,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  updated_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.mc_audit_device_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_mc_audit_device_links" ON public.mc_audit_device_links
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── mc_site_health_view (VIEW -- definition must be recreated manually)
-- NOTE: mc_site_health_view is a database view. Recreate from Supabase SQL Editor.


-- ── mc_active_alerts_view (VIEW -- definition must be recreated manually)
-- NOTE: mc_active_alerts_view is a database view. Recreate from Supabase SQL Editor.


-- ================================================================
-- GROUP: Audit System
-- ================================================================

-- ── site_audits ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.site_audits (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  created_at timestamp with time zone DEFAULT now(),
  client_id                                integer,
  device_id                                integer,
  audit_date                               date  NOT NULL,
  status                                   text,
  notes                                    text,
  performed_by                             text,
  audit_time timestamp with time zone,
  checks                                   text
);

ALTER TABLE public.site_audits ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_site_audits" ON public.site_audits
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── site_audit_clients ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.site_audit_clients (
  itflow_id                                integer  NOT NULL,
  name                                     text  NOT NULL,
  last_sync                                text
);

ALTER TABLE public.site_audit_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_site_audit_clients" ON public.site_audit_clients
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── site_audit_devices ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.site_audit_devices (
  itflow_asset_id                          integer  NOT NULL,
  client_id                                integer,
  name                                     text,
  type                                     text,
  serial                                   text,
  last_sync                                text
);

ALTER TABLE public.site_audit_devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_site_audit_devices" ON public.site_audit_devices
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── audit_findings ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.audit_findings (
  finding_id                               uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  audit_batch_id                           uuid,
  serial_number                            text,
  severity                                 text,
  category                                 text,
  finding_summary                          text,
  recommended_action                       text,
  resolved                                 boolean,
  resolved_date                            date,
  created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.audit_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_audit_findings" ON public.audit_findings
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── offline_audits ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.offline_audits (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  created_at timestamp with time zone DEFAULT now(),
  device_type                              text,
  brand_model                              text,
  date_of_purchase                         date,
  serial_number                            text,
  assigned_user_room                       text,
  intended_use                             text,
  connectivity                             text,
  recording_storage_capabilities           text,
  security_settings_applied                text,
  os_update_status                         text,
  camera_sync_status                       boolean,
  onedrive_sync_status                     boolean,
  photos_count                             integer,
  photos_date                              date,
  total_photos_count                       integer,
  notes                                    text
);

ALTER TABLE public.offline_audits ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_offline_audits" ON public.offline_audits
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── reports ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.reports (
  report_id                                uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  audit_batch_id                           uuid,
  site_id                                  uuid,
  report_name                              text,
  report_type                              text,
  report_url                               text,
  created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_reports" ON public.reports
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── report_requests ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.report_requests (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  created_at timestamp with time zone DEFAULT now()  NOT NULL,
  site_name                                text  NOT NULL,
  target_date                              date  NOT NULL,
  status                                   text,
  message                                  text,
  agent_name                               text
);

ALTER TABLE public.report_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_report_requests" ON public.report_requests
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ================================================================
-- GROUP: Agent / Continuity
-- ================================================================

-- ── agent_memories ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.agent_memories (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  created_at timestamp with time zone DEFAULT now(),
  content                                  text  NOT NULL,
  embedding                                text,
  category                                 text,
  importance                               integer
);

ALTER TABLE public.agent_memories ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_agent_memories" ON public.agent_memories
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── agent_logs ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.agent_logs (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  agent_name                               text,
  task_description                         text,
  model_used                               text,
  status                                   text,
  created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE public.agent_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_agent_logs" ON public.agent_logs
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── conversation_continuity ────────────────────────────────
CREATE TABLE IF NOT EXISTS public.conversation_continuity (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  created_at timestamp with time zone DEFAULT now(),
  turn_summary                             text  NOT NULL,
  session_id                               text
);

ALTER TABLE public.conversation_continuity ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_conversation_continuity" ON public.conversation_continuity
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── todos ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.todos (
  id                                       uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  title                                    text  NOT NULL,
  category                                 text  NOT NULL,
  priority                                 text  NOT NULL,
  due_date                                 date,
  completed                                boolean  NOT NULL,
  status                                   text  NOT NULL,
  track_status                             text,
  created_at timestamp with time zone DEFAULT now()  NOT NULL
);

ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all_todos" ON public.todos
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ================================================================
-- Indexes
-- ================================================================

CREATE INDEX IF NOT EXISTS idx_device_audits_site_id ON public.device_audits(site_id);
CREATE INDEX IF NOT EXISTS idx_device_audits_audit_date ON public.device_audits(audit_date);
CREATE INDEX IF NOT EXISTS idx_audit_entries_audit_batch_id ON public.audit_entries(audit_batch_id);
CREATE INDEX IF NOT EXISTS idx_audit_entries_site_id ON public.audit_entries(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_site_id ON public.devices(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON public.devices(is_active);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_site_id ON public.remediation_actions(site_id);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_status ON public.remediation_actions(status);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_due_date ON public.remediation_actions(due_date);
CREATE INDEX IF NOT EXISTS idx_incidents_site_id ON public.incidents(site_id);
CREATE INDEX IF NOT EXISTS idx_incidents_mandatory_reportable ON public.incidents(mandatory_reportable);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents(status);
CREATE INDEX IF NOT EXISTS idx_mc_network_devices_site_id ON public.mc_network_devices(site_id);
CREATE INDEX IF NOT EXISTS idx_mc_device_observations_device_id ON public.mc_device_observations(device_id);
CREATE INDEX IF NOT EXISTS idx_mc_probe_heartbeats_probe_id ON public.mc_probe_heartbeats(probe_id);
CREATE INDEX IF NOT EXISTS idx_agent_logs_agent_id ON public.agent_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_mc_probe_agents_heartbeat ON public.mc_probe_agents(last_heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS idx_mc_device_patterns_device ON public.mc_device_patterns(device_id);
CREATE INDEX IF NOT EXISTS idx_mc_agent_releases_version ON public.mc_agent_releases(version DESC);

-- Unique constraint for upsert on (site_id, mac_address)
ALTER TABLE public.mc_network_devices
  DROP CONSTRAINT IF EXISTS uq_site_mac,
  ADD CONSTRAINT uq_site_mac UNIQUE NULLS NOT DISTINCT (site_id, mac_address);

-- ================================================================
-- NOTES
-- ================================================================
--
-- Views (mc_site_health_view, mc_active_alerts_view) are not included
-- as CREATE TABLE statements above will fail for views. Recreate these
-- from the Supabase SQL Editor using the original view definitions.
--
-- Row Level Security policies above grant full access to service_role.
-- Adjust policies for anon/authenticated roles as required for your
-- application access pattern.
--
-- ================================================================
-- Table Comments
-- ================================================================

COMMENT ON TABLE public.sites IS 'Per-site config: ACECQA policy checklist, audit thresholds, SharePoint integration';
COMMENT ON TABLE public.devices IS 'Device inventory register across all sites (26-field)';
COMMENT ON TABLE public.device_audits IS 'Audit batch records — one per audit session per site';
COMMENT ON TABLE public.audit_entries IS 'Per-device entries within each audit batch';
COMMENT ON TABLE public.remediation_actions IS 'Corrective actions arising from audit findings';
COMMENT ON TABLE public.incidents IS 'ACECQA mandatory incident register with regulatory notification tracking';
COMMENT ON TABLE public.mc_sites IS 'Network monitoring: site definitions for probe agents';
COMMENT ON TABLE public.mc_probe_agents IS 'Network monitoring: probe agent registration';
COMMENT ON TABLE public.mc_network_devices IS 'Network monitoring: discovered network devices';
COMMENT ON TABLE public.agent_memories IS 'AI agent persistent memory store';
COMMENT ON TABLE public.conversation_continuity IS 'AI agent conversation state';