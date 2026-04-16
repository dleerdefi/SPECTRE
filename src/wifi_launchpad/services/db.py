"""PostgreSQL persistence — best-effort writes for scan/attack data."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import AttackTargetResult, Handshake
from wifi_launchpad.domain.survey import Client, Network, ScanResult

logger = logging.getLogger(__name__)


class DatabaseService:
    """Best-effort PostgreSQL writes. Never crashes the caller on DB failure."""

    def __init__(self) -> None:
        self._conn = None

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

    # ── Network upserts ──────────────────────────────────────────────────

    def save_networks(self, networks: List[Network]) -> int:
        """Upsert networks by BSSID. Returns count saved."""
        if not self.connected:
            return 0

        saved = 0
        for net in networks:
            try:
                enc = net.encryption.value if hasattr(net.encryption, "value") else str(net.encryption)
                self._conn.execute(
                    """
                    INSERT INTO networks (
                        bssid, ssid, channel, encryption, cipher,
                        authentication, signal_strength, beacons,
                        data_packets, wps_enabled, wps_locked,
                        manufacturer, first_seen, last_seen,
                        hidden
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (bssid) DO UPDATE SET
                        ssid = COALESCE(NULLIF(EXCLUDED.ssid, ''), networks.ssid),
                        channel = EXCLUDED.channel,
                        signal_strength = EXCLUDED.signal_strength,
                        beacons = networks.beacons + EXCLUDED.beacons,
                        data_packets = networks.data_packets + EXCLUDED.data_packets,
                        last_seen = EXCLUDED.last_seen
                    """,
                    (
                        net.bssid, net.ssid, net.channel, enc,
                        net.cipher, net.authentication, net.signal_strength,
                        net.beacon_rate, net.data_packets, net.wps_enabled,
                        net.wps_locked, net.manufacturer,
                        net.first_seen, net.last_seen, net.hidden,
                    ),
                )
                saved += 1
            except Exception as exc:
                logger.debug("Network upsert failed for %s: %s", net.bssid, exc)

        try:
            self._conn.commit()
        except Exception:
            pass
        return saved

    # ── Client upserts ───────────────────────────────────────────────────

    def save_clients(self, clients: List[Client]) -> int:
        """Upsert clients by MAC. Returns count saved."""
        if not self.connected:
            return 0

        saved = 0
        for client in clients:
            try:
                self._conn.execute(
                    """
                    INSERT INTO clients (
                        mac_address, associated_bssid, manufacturer,
                        device_type, signal_strength, packets_sent,
                        probed_ssids, first_seen, last_seen
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (mac_address) DO UPDATE SET
                        associated_bssid = COALESCE(EXCLUDED.associated_bssid, clients.associated_bssid),
                        signal_strength = EXCLUDED.signal_strength,
                        packets_sent = clients.packets_sent + EXCLUDED.packets_sent,
                        last_seen = EXCLUDED.last_seen
                    """,
                    (
                        client.mac_address, client.associated_bssid,
                        client.manufacturer, client.device_type,
                        client.signal_strength, client.packets_sent,
                        client.probed_ssids, client.first_seen, client.last_seen,
                    ),
                )
                saved += 1
            except Exception as exc:
                logger.debug("Client upsert failed for %s: %s", client.mac_address, exc)

        try:
            self._conn.commit()
        except Exception:
            pass
        return saved

    # ── Handshake inserts ────────────────────────────────────────────────

    def save_handshake(self, handshake: Handshake) -> bool:
        """Insert a captured handshake."""
        if not self.connected:
            return False

        try:
            self._conn.execute(
                """
                INSERT INTO handshakes (
                    network_id, client_mac, capture_time,
                    eapol_packets, quality_score, pcap_file,
                    file_size, handshake_type, is_complete,
                    crack_status
                ) VALUES (
                    (SELECT id FROM networks WHERE bssid = %s LIMIT 1),
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    handshake.bssid, handshake.client_mac,
                    handshake.capture_time, handshake.eapol_packets,
                    handshake.quality_score, handshake.pcap_file,
                    handshake.file_size, handshake.capture_method,
                    handshake.is_complete,
                    "cracked" if handshake.cracked else "pending",
                ),
            )
            self._conn.commit()
            return True
        except Exception as exc:
            logger.debug("Handshake insert failed: %s", exc)
            return False

    # ── Attack log inserts ───────────────────────────────────────────────

    def save_attack_log(self, result: AttackTargetResult) -> bool:
        """Log an attack attempt."""
        if not self.connected:
            return False

        try:
            self._conn.execute(
                """
                INSERT INTO attack_logs (
                    bssid, ssid, techniques_tried, captured,
                    skipped, skip_reason, eapol_packets,
                    total_time, password, attack_time
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    result.network_bssid, result.network_ssid,
                    result.techniques_tried, result.captured,
                    result.skipped, result.skip_reason,
                    result.eapol_packets_seen, result.total_time,
                    result.crack_result.password if result.crack_result and result.crack_result.cracked else None,
                    datetime.now(),
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
