-- SPECTRE Migration 003: Multi-tool pipeline enrichment
-- Adds WPS columns, traffic observations, and attack escalation tracking.

-- ── WPS data from wash scans ───────────────────────────────────────────
ALTER TABLE networks ADD COLUMN IF NOT EXISTS wps_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE networks ADD COLUMN IF NOT EXISTS wps_version TEXT;
ALTER TABLE networks ADD COLUMN IF NOT EXISTS wps_locked BOOLEAN DEFAULT FALSE;

-- Track which tool produced each observation
ALTER TABLE networks ADD COLUMN IF NOT EXISTS source_tool TEXT DEFAULT 'unknown';

-- ── Traffic observations from tshark live capture ──────────────────────
CREATE TABLE IF NOT EXISTS traffic_observations (
    id BIGSERIAL,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bssid MACADDR,
    protocol TEXT,                -- HTTP, DNS, FTP, Telnet, etc.
    detail TEXT,                  -- URL, query, credential hint
    cleartext BOOLEAN DEFAULT FALSE,
    collector_node TEXT NOT NULL,
    PRIMARY KEY (time, id)
);

SELECT create_hypertable('traffic_observations', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE);

SELECT add_retention_policy('traffic_observations', INTERVAL '90 days',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_traffic_bssid ON traffic_observations(bssid);
CREATE INDEX IF NOT EXISTS idx_traffic_cleartext ON traffic_observations(cleartext)
    WHERE cleartext = TRUE;

-- ── Attack escalation tracking ─────────────────────────────────────────
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS attack_step TEXT;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS target_score FLOAT;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS user_approved BOOLEAN DEFAULT FALSE;
