-- SPECTRE Migration 002: Convert event tables to hypertables, add indexes,
-- and introduce the wifi_learned_rules table for the LLM feedback loop.

-- ── Convert additional time-series tables to hypertables ──────────────
-- These have 'time' columns but were not converted in 001-schema.sql.

SELECT create_hypertable('security_events', 'time',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE);

SELECT create_hypertable('attack_logs', 'time',
    chunk_time_interval => INTERVAL '30 days',
    if_not_exists => TRUE);

-- ── Retention policies for event-style tables ────────────────────────

SELECT add_retention_policy('security_events', INTERVAL '180 days', if_not_exists => TRUE);
SELECT add_retention_policy('attack_logs', INTERVAL '365 days', if_not_exists => TRUE);

-- ── Missing indexes for query performance ────────────────────────────

-- Recent analyses: "show me the last 20 LLM runs"
CREATE INDEX IF NOT EXISTS idx_analysis_created
    ON analysis_results(created_at DESC);

-- FK lookups: "corrections for this analysis"
CREATE INDEX IF NOT EXISTS idx_corrections_analysis
    ON analysis_corrections(analysis_id);

-- Recent handshakes
CREATE INDEX IF NOT EXISTS idx_handshakes_captured
    ON handshakes(captured_at DESC);

-- "Show me uncracked handshakes" — partial index for efficiency
CREATE INDEX IF NOT EXISTS idx_handshakes_uncracked
    ON handshakes(cracked, captured_at DESC)
    WHERE cracked = FALSE;

-- Campaign summaries: "what did I capture today"
CREATE INDEX IF NOT EXISTS idx_attack_captured
    ON attack_logs(captured, time DESC);

-- ── LLM learned rules (regular table, NOT time-series) ───────────────
-- Distilled from corrections by external LLM review. Low-volume relational
-- data; hypertables would add overhead without benefit.

CREATE TABLE IF NOT EXISTS wifi_learned_rules (
    id BIGSERIAL PRIMARY KEY,
    rule_text TEXT NOT NULL,
    source TEXT NOT NULL,       -- e.g., claude-opus-4-6, human
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_created
    ON wifi_learned_rules(created_at DESC);
