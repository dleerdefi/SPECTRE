"""PostgreSQL persistence — best-effort writes for scan/attack data.

Schema is TimescaleDB with hypertables on time-series tables (networks, clients,
security_events, attack_logs) and regular tables for relational data (analysis_*,
learned_rules). All time-series inserts are append-only — the time column IS the
observation timestamp. MAC addresses are hashed for privacy via schema helper.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import AttackTargetResult, Handshake
from wifi_launchpad.domain.survey import Client, Network, ScanResult
from wifi_launchpad.services.db_analysis import AnalysisMixin
from wifi_launchpad.services.db_rules import LearnedRulesMixin

logger = logging.getLogger(__name__)


def _hash_mac(mac: Optional[str]) -> Optional[str]:
    """Hash a MAC address via SHA-256 for privacy-preserving storage.

    Mirrors the schema's hash_mac() SQL function so Python and SQL produce the
    same hash for joining/lookups.
    """
    if not mac:
        return None
    return hashlib.sha256(mac.encode("utf-8")).hexdigest()


class DatabaseService(AnalysisMixin, LearnedRulesMixin):
    """Best-effort PostgreSQL writes. Never crashes the caller on DB failure."""

    def __init__(self) -> None:
        self._conn = None
        self._node = get_settings().db.collector_node

    def connect(self) -> bool:
        cfg = get_settings().db
        if not cfg.password:
            logger.warning(
                "DB_PASSWORD not configured — set it in .env or environment. "
                "Skipping database connection."
            )
            return False

        try:
            import psycopg

            self._conn = psycopg.connect(
                host=cfg.host,
                port=cfg.port,
                dbname=cfg.dbname,
                user=cfg.user,
                password=cfg.password,
                connect_timeout=cfg.connect_timeout,
            )
            logger.info("Connected to PostgreSQL at %s:%s", cfg.host, cfg.port)
            return True
        except Exception as exc:
            logger.warning("Database connection failed (non-fatal): %s", exc)
            self._conn = None
            return False

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    @property
    def connected(self) -> bool:
        return self._conn is not None and not self._conn.closed

    # ── Networks (time-series hypertable) ────────────────────────────────

    def save_networks(self, networks: List[Network]) -> int:
        """Append network observations to the time-series hypertable."""
        if not self.connected:
            return 0

        saved = 0
        now = datetime.now()
        for net in networks:
            try:
                enc = net.encryption.value if hasattr(net.encryption, "value") else str(net.encryption)
                # Preserve non-schema fields in raw_data JSONB
                extras = {"hidden": getattr(net, "hidden", None)}
                raw_data = json.dumps({k: v for k, v in extras.items() if v is not None})

                self._conn.execute(
                    """
                    INSERT INTO networks (
                        time, bssid, ssid, channel, frequency, signal_strength,
                        encryption, cipher, authentication, manufacturer,
                        beacon_rate, data_rate, wps_enabled, wps_locked,
                        wps_version, source_tool, collector_node, raw_data
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s::jsonb
                    )
                    """,
                    (
                        now, net.bssid, net.ssid, net.channel,
                        getattr(net, "frequency", None), net.signal_strength,
                        enc, net.cipher, net.authentication, net.manufacturer,
                        net.beacon_rate, getattr(net, "data_packets", 0),
                        getattr(net, "wps_enabled", False),
                        getattr(net, "wps_locked", False),
                        getattr(net, "wps_version", None),
                        "native", self._node, raw_data,
                    ),
                )
                saved += 1
            except Exception as exc:
                logger.debug("Network insert failed for %s: %s", net.bssid, exc)

        try:
            self._conn.commit()
        except Exception:
            pass
        return saved

    # ── Clients (time-series hypertable, MAC-hashed) ─────────────────────

    def save_clients(self, clients: List[Client]) -> int:
        """Append client observations with hashed MACs."""
        if not self.connected:
            return 0

        saved = 0
        now = datetime.now()
        for client in clients:
            try:
                mac_hash = _hash_mac(client.mac_address)
                if not mac_hash:
                    continue

                # Preserve device_type and other metadata in JSONB
                fingerprint = {
                    "device_type": getattr(client, "device_type", None),
                }
                fingerprint_json = json.dumps(
                    {k: v for k, v in fingerprint.items() if v is not None}
                )
                probes = getattr(client, "probed_ssids", None) or []

                self._conn.execute(
                    """
                    INSERT INTO clients (
                        time, mac_hash, mac_vendor, associated_bssid,
                        signal_strength, packets_sent, packets_received,
                        probe_requests, device_fingerprint, last_activity,
                        collector_node
                    ) VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s::jsonb, %s,
                        %s
                    )
                    """,
                    (
                        now, mac_hash, getattr(client, "manufacturer", None),
                        client.associated_bssid,
                        client.signal_strength,
                        getattr(client, "packets_sent", 0),
                        getattr(client, "packets_received", 0),
                        probes, fingerprint_json, now,
                        self._node,
                    ),
                )
                saved += 1
            except Exception as exc:
                logger.debug("Client insert failed for %s: %s", client.mac_address, exc)

        try:
            self._conn.commit()
        except Exception:
            pass
        return saved

    # ── Handshakes (regular table, kept indefinitely) ────────────────────

    def save_handshake(self, handshake: Handshake) -> bool:
        """Insert a captured handshake."""
        if not self.connected:
            return False

        try:
            self._conn.execute(
                """
                INSERT INTO handshakes (
                    captured_at, bssid, ssid, client_mac_hash,
                    capture_file, cracked, password, collector_node
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    getattr(handshake, "capture_time", datetime.now()),
                    handshake.bssid,
                    getattr(handshake, "ssid", None),
                    _hash_mac(getattr(handshake, "client_mac", None)),
                    getattr(handshake, "pcap_file", None),
                    bool(getattr(handshake, "cracked", False)),
                    getattr(handshake, "password", None),
                    self._node,
                ),
            )
            self._conn.commit()
            return True
        except Exception as exc:
            logger.debug("Handshake insert failed: %s", exc)
            return False

    # ── Attack logs (time-series hypertable) ─────────────────────────────

    def save_attack_log(self, result: AttackTargetResult) -> bool:
        """Log an attack attempt."""
        if not self.connected:
            return False

        try:
            password = None
            if result.crack_result and result.crack_result.cracked:
                password = result.crack_result.password

            self._conn.execute(
                """
                INSERT INTO attack_logs (
                    time, bssid, ssid, techniques_tried, captured,
                    skipped, skip_reason, eapol_packets,
                    total_time, password, attack_step, target_score,
                    user_approved, collector_node
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                )
                """,
                (
                    datetime.now(),
                    result.network_bssid, result.network_ssid,
                    result.techniques_tried, result.captured,
                    result.skipped, result.skip_reason,
                    result.eapol_packets_seen, result.total_time,
                    password,
                    getattr(result, "attack_step", None),
                    getattr(result, "target_score", None),
                    getattr(result, "user_approved", False),
                    self._node,
                ),
            )
            self._conn.commit()
            return True
        except Exception as exc:
            logger.debug("Attack log insert failed: %s", exc)
            return False

    # ── Bulk save helpers ────────────────────────────────────────────────

    def save_scan(self, scan_results: ScanResult) -> Dict[str, int]:
        """Save full scan results. Returns counts."""
        nets = self.save_networks(scan_results.networks)
        clients = self.save_clients(scan_results.clients)
        logger.info("Saved %d networks, %d clients to DB", nets, clients)
        return {"networks": nets, "clients": clients}

    def save_campaign(self, results: List[AttackTargetResult]) -> Dict[str, int]:
        """Save campaign results. Returns counts."""
        handshakes = 0
        logs = 0
        for r in results:
            if self.save_attack_log(r):
                logs += 1
            if r.captured and r.handshake:
                if self.save_handshake(r.handshake):
                    handshakes += 1
        logger.info("Saved %d attack logs, %d handshakes to DB", logs, handshakes)
        return {"attack_logs": logs, "handshakes": handshakes}
