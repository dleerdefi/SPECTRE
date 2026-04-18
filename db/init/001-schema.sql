-- SPECTRE Database Schema
-- TimescaleDB with PostGIS for time-series WiFi data and GPS coordinates

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Custom types
CREATE TYPE encryption_type AS ENUM (
    'Open', 'WEP', 'WPA', 'WPA2', 'WPA3', 'WPA2/WPA3', 'WPA/WPA2',
    'WPS', 'Enterprise', 'Unknown'
);
CREATE TYPE event_severity AS ENUM (
    'info', 'low', 'medium', 'high', 'critical'
);

-- ── Networks (time-series) ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS networks (
    time TIMESTAMPTZ NOT NULL,
    bssid MACADDR NOT NULL,
    ssid TEXT,
    channel SMALLINT CHECK (channel BETWEEN 1 AND 165),
    frequency INTEGER,
    signal_strength SMALLINT CHECK (signal_strength BETWEEN -100 AND 0),
    encryption encryption_type DEFAULT 'Unknown',
    cipher TEXT,
    authentication TEXT,
    manufacturer TEXT,
    beacon_rate INTEGER,
    data_rate INTEGER,
    location GEOGRAPHY(POINT, 4326),
    collector_node TEXT NOT NULL,
    raw_data JSONB,
    PRIMARY KEY (time, bssid, collector_node)
);

SELECT create_hypertable('networks', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);
CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid);
CREATE INDEX IF NOT EXISTS idx_networks_channel ON networks(channel);
CREATE INDEX IF NOT EXISTS idx_networks_signal ON networks(signal_strength);
CREATE INDEX IF NOT EXISTS idx_networks_encryption ON networks(encryption);
CREATE INDEX IF NOT EXISTS idx_networks_location ON networks USING GIST(location);

-- ── Clients ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clients (
    time TIMESTAMPTZ NOT NULL,
    mac_hash TEXT NOT NULL,
    mac_vendor TEXT,
    associated_bssid MACADDR,
    signal_strength SMALLINT CHECK (signal_strength BETWEEN -100 AND 0),
    packets_sent INTEGER DEFAULT 0,
    packets_received INTEGER DEFAULT 0,
    data_bytes BIGINT DEFAULT 0,
    probe_requests TEXT[],
    device_fingerprint JSONB,
    last_activity TIMESTAMPTZ,
    collector_node TEXT NOT NULL,
    PRIMARY KEY (time, mac_hash, collector_node)
);

SELECT create_hypertable('clients', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_clients_hash ON clients(mac_hash);
CREATE INDEX IF NOT EXISTS idx_clients_bssid ON clients(associated_bssid);
CREATE INDEX IF NOT EXISTS idx_clients_vendor ON clients(mac_vendor);
CREATE INDEX IF NOT EXISTS idx_clients_probes ON clients USING GIN(probe_requests);

-- ── Security events ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type TEXT NOT NULL,
    severity event_severity NOT NULL,
    source_mac TEXT,
    target_mac TEXT,
    affected_bssid MACADDR,
    description TEXT,
    details JSONB,
    detected_by TEXT NOT NULL,
    collector_node TEXT NOT NULL,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    false_positive BOOLEAN DEFAULT FALSE,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_bssid ON security_events(affected_bssid);

-- ── Handshakes ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS handshakes (
    id BIGSERIAL PRIMARY KEY,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bssid MACADDR NOT NULL,
    ssid TEXT,
    client_mac_hash TEXT,
    eapol_msg1 BYTEA,
    eapol_msg2 BYTEA,
    eapol_msg3 BYTEA,
    eapol_msg4 BYTEA,
    pmkid TEXT,
    capture_file TEXT,
    cracked BOOLEAN DEFAULT FALSE,
    password TEXT,
    crack_time INTERVAL,
    collector_node TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handshakes_bssid ON handshakes(bssid);
CREATE INDEX IF NOT EXISTS idx_handshakes_cracked ON handshakes(cracked);

-- ── Attack logs ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attack_logs (
    id BIGSERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bssid MACADDR,
    ssid TEXT,
    techniques_tried TEXT[],
    captured BOOLEAN DEFAULT FALSE,
    skipped BOOLEAN DEFAULT FALSE,
    skip_reason TEXT,
    eapol_packets INTEGER,
    total_time FLOAT,
    password TEXT,
    collector_node TEXT NOT NULL
);

-- ── Vulnerability scores ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vulnerability_scores (
    id BIGSERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bssid MACADDR NOT NULL,
    ssid TEXT,
    score FLOAT CHECK (score BETWEEN 0 AND 100),
    factors JSONB,
    collector_node TEXT NOT NULL
);

-- ── Analysis results (LLM) ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS analysis_results (
    id BIGSERIAL PRIMARY KEY,
    scan_data TEXT,
    full_response TEXT,
    full_transcript TEXT,
    risk_level VARCHAR(20),
    summary TEXT,
    model_name VARCHAR(200),
    rounds INTEGER,
    auto_attack BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analysis_vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analysis_results(id),
    name TEXT,
    severity VARCHAR(20),
    confidence VARCHAR(20) DEFAULT 'possible',
    evidence TEXT DEFAULT '',
    bssid VARCHAR(20),
    ssid VARCHAR(100),
    description TEXT,
    attack TEXT,
    fix TEXT
);

CREATE TABLE IF NOT EXISTS analysis_corrections (
    id BIGSERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analysis_results(id),
    vuln_id INTEGER REFERENCES analysis_vulnerabilities(id),
    original_finding TEXT,
    correction TEXT,
    corrected_by VARCHAR(100),
    correction_type VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Collector nodes ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS collector_nodes (
    node_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip_address INET,
    location TEXT,
    capabilities JSONB,
    status TEXT DEFAULT 'offline',
    last_seen TIMESTAMPTZ,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    version TEXT,
    config JSONB
);

-- ── Aggregation views ───────────────────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_network_stats AS
SELECT
    time_bucket('1 hour', time) AS hour,
    bssid, ssid, channel,
    COUNT(*) AS beacon_count,
    AVG(signal_strength) AS avg_signal,
    MAX(signal_strength) AS max_signal,
    MIN(signal_strength) AS min_signal,
    collector_node
FROM networks
GROUP BY hour, bssid, ssid, channel, collector_node
WITH NO DATA;

-- ── Retention and compression ───────────────────────────────────────

SELECT add_retention_policy('networks', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('clients', INTERVAL '90 days', if_not_exists => TRUE);

SELECT add_compression_policy('networks', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('clients', INTERVAL '7 days', if_not_exists => TRUE);

-- ── Helper functions ────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION hash_mac(mac_address TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(digest(mac_address, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ── Auto-update collector last_seen ─────────────────────────────────

CREATE OR REPLACE FUNCTION update_node_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE collector_nodes
    SET last_seen = NOW(), status = 'online'
    WHERE node_id = NEW.collector_node;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_node_on_network_insert
AFTER INSERT ON networks
FOR EACH ROW
EXECUTE FUNCTION update_node_last_seen();
