-- Phase 1: Schema Migration for Probe Agent Platform Redesign
-- Run this in Supabase SQL editor

-- 1. Convert text JSON columns to jsonb
ALTER TABLE IF EXISTS public.mc_probe_agents
  ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;

ALTER TABLE IF EXISTS public.mc_network_devices
  ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;

ALTER TABLE IF EXISTS public.mc_device_observations
  ALTER COLUMN raw TYPE jsonb USING raw::jsonb;

ALTER TABLE IF EXISTS public.mc_alerts
  ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;

ALTER TABLE IF EXISTS public.mc_probe_heartbeats
  ALTER COLUMN payload TYPE jsonb USING payload::jsonb;

-- 2. Unique constraint for upsert (site_id + mac_address, non-null only)
-- PostgreSQL default: NULLs are distinct, so (site_id, NULL) rows don't conflict
ALTER TABLE public.mc_network_devices
  DROP CONSTRAINT IF EXISTS uq_site_mac,
  ADD CONSTRAINT uq_site_mac UNIQUE (site_id, mac_address);

-- 3. Index for agent health queries
CREATE INDEX IF NOT EXISTS idx_mc_probe_agents_heartbeat
  ON public.mc_probe_agents(last_heartbeat_at DESC);

-- 4. Upsert devices in a single transaction
CREATE OR REPLACE FUNCTION public.upsert_devices(
  p_site_id UUID,
  p_agent_id UUID,
  p_devices JSONB
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_inserted INT := 0;
  v_updated INT := 0;
  v_seen_ids UUID[] := '{}';
  v_device JSONB;
  v_device_id UUID;
    v_ip TEXT;
    v_ip_inet INET;
    v_mac TEXT;
  v_hostname TEXT;
  v_vendor TEXT;
  v_device_type TEXT;
  v_friendly_name TEXT;
  v_status TEXT;
  v_latency_ms NUMERIC;
BEGIN
  FOR v_device IN SELECT * FROM jsonb_array_elements(p_devices) LOOP
    v_ip := v_device->>'ip_address';
    v_mac := v_device->>'mac_address';
    v_hostname := v_device->>'hostname';
    v_vendor := v_device->>'vendor';
    v_device_type := v_device->>'device_type';
    v_friendly_name := v_device->>'friendly_name';
    v_status := COALESCE(v_device->>'status', 'ONLINE');
    v_latency_ms := (v_device->>'latency_ms')::numeric;

    v_ip_inet := CASE WHEN v_ip ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' THEN v_ip::inet ELSE NULL END;

    INSERT INTO public.mc_network_devices (
      site_id, last_seen_by_agent_id, ip_address, mac_address,
      hostname, vendor, device_type, friendly_name,
      status, last_seen_at, last_online_at, last_latency_ms,
      expected_online, updated_at
    ) VALUES (
      p_site_id, p_agent_id,
      v_ip_inet, v_mac,
      v_hostname, v_vendor, v_device_type, v_friendly_name,
      v_status, NOW(),
      CASE WHEN v_status = 'ONLINE' THEN NOW() ELSE NULL END,
      v_latency_ms,
      TRUE, NOW()
    )
    ON CONFLICT (site_id, mac_address) DO UPDATE SET
      ip_address = EXCLUDED.ip_address,
      hostname = EXCLUDED.hostname,
      vendor = EXCLUDED.vendor,
      device_type = EXCLUDED.device_type,
      friendly_name = EXCLUDED.friendly_name,
      status = EXCLUDED.status,
      last_seen_at = EXCLUDED.last_seen_at,
      last_online_at = EXCLUDED.last_online_at,
      last_latency_ms = EXCLUDED.last_latency_ms,
      last_seen_by_agent_id = EXCLUDED.last_seen_by_agent_id,
      updated_at = EXCLUDED.updated_at
    RETURNING id INTO v_device_id;

    v_seen_ids := array_append(v_seen_ids, v_device_id);
  END LOOP;

  RETURN jsonb_build_object(
    'inserted', v_inserted,
    'updated', v_updated,
    'seen_device_ids', to_jsonb(v_seen_ids)
  );
END;
$$;

-- 5. Bulk insert observations
DROP FUNCTION IF EXISTS public.bulk_insert_observations CASCADE;
CREATE OR REPLACE FUNCTION public.bulk_insert_observations(
  p_observations JSONB
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_count INT := 0;
BEGIN
  INSERT INTO public.mc_device_observations (
    site_id, agent_id, device_id, observed_at,
    ip_address, mac_address, hostname, status,
    latency_ms, packet_loss_percent, method, raw
  )
  SELECT
    (item->>'site_id')::UUID,
    (item->>'agent_id')::UUID,
    (item->>'device_id')::UUID,
    COALESCE((item->>'observed_at')::TIMESTAMPTZ, NOW()),
    CASE WHEN item->>'ip_address' ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
         THEN (item->>'ip_address')::inet ELSE NULL END,
    item->>'mac_address',
    item->>'hostname',
    COALESCE(item->>'status', 'ONLINE'),
    (item->>'latency_ms')::numeric,
    (item->>'packet_loss_percent')::numeric,
    item->>'method',
    (item->>'raw')::jsonb
  FROM jsonb_array_elements(p_observations) AS item;

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN jsonb_build_object('inserted', v_count);
END;
$$;

-- 6. Offline sweep as a single query
CREATE OR REPLACE FUNCTION public.sweep_offline_devices(
  p_site_id UUID,
  p_seen_device_ids UUID[],
  p_offline_after_seconds INT DEFAULT 180
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_marked INT := 0;
BEGIN
  UPDATE public.mc_network_devices
  SET status = 'OFFLINE',
      last_offline_at = NOW(),
      updated_at = NOW()
  WHERE site_id = p_site_id
    AND expected_online = TRUE
    AND status NOT IN ('OFFLINE', 'DISABLED')
    AND last_seen_at < NOW() - (p_offline_after_seconds || ' seconds')::INTERVAL
    AND id != ALL(p_seen_device_ids);

  GET DIAGNOSTICS v_marked = ROW_COUNT;
  RETURN jsonb_build_object('marked_offline', v_marked);
END;
$$;
