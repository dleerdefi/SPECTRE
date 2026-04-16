"""Recon intelligence analysis — turns raw scan data into actionable attack plans."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from wifi_launchpad.domain.recon import ReconReport, TargetIntel
from wifi_launchpad.domain.survey import Client, EncryptionType, Network, ScanResult

logger = logging.getLogger(__name__)


def build_recon_report(scan_results: ScanResult) -> ReconReport:
    """Analyze scan results and produce an intelligence report."""

    report = ReconReport(generated_at=datetime.now())
    report.total_networks = len(scan_results.networks)
    report.total_clients = len(scan_results.clients)

    # Count categories
    for net in scan_results.networks:
        if net.encryption == EncryptionType.WPA3:
            report.wpa3_count += 1
        elif net.encryption == EncryptionType.OPEN:
            report.open_count += 1
        elif net.encryption == EncryptionType.ENTERPRISE:
            report.enterprise_count += 1
        if net.hidden:
            report.hidden_count += 1
        if net.wps_enabled:
            report.wps_enabled.append(net.ssid or net.bssid)

    # Probe request analysis — reveals hidden SSIDs and client behavior
    for client in scan_results.clients:
        for ssid in client.probed_ssids:
            if ssid:
                report.probe_leaks.setdefault(ssid, []).append(client.mac_address)

    # Build target intelligence for crackable networks
    for net in scan_results.networks:
        if net.encryption in {EncryptionType.OPEN, EncryptionType.ENTERPRISE, EncryptionType.WPA3}:
            continue
        if net.hidden or not net.ssid or net.ssid.startswith("<"):
            continue
        if net.signal_strength >= 0 or net.channel <= 0:
            continue

        clients = scan_results.get_associated_clients(net.bssid)
        intel = _analyze_target(net, clients)
        report.targets.append(intel)

    # Sort by priority score descending
    report.targets.sort(key=lambda t: t.priority_score, reverse=True)

    return report


def _analyze_target(network: Network, clients: List[Client]) -> TargetIntel:
    """Build intelligence for a single target network."""

    intel = TargetIntel(network=network, clients=clients)

    # Find the most active client by packet count
    if clients:
        best = max(clients, key=lambda c: c.packets_sent + c.packets_received)
        intel.best_client = best
        intel.total_client_packets = sum(c.packets_sent + c.packets_received for c in clients)

    # Determine attack vectors
    vectors = []
    if clients:
        high_traffic = [c for c in clients if c.packets_sent > 1000]
        if high_traffic:
            vectors.append("high-traffic-client")
        if len(clients) >= 3:
            vectors.append("multiple-clients")
        elif len(clients) >= 1:
            vectors.append("client-available")

    if network.wps_enabled and not network.wps_locked:
        vectors.append("wps-unlocked")
    elif network.wps_enabled:
        vectors.append("wps-locked")

    if network.signal_strength > -50:
        vectors.append("strong-signal")
    elif network.signal_strength > -70:
        vectors.append("moderate-signal")
    else:
        vectors.append("weak-signal")

    enc_val = network.encryption.value if hasattr(network.encryption, "value") else ""
    if "WPA2" in enc_val and "WPA" in enc_val:
        vectors.append("mixed-wpa")

    intel.attack_vectors = vectors

    # Recommend technique
    intel.recommended_technique = _recommend_technique(network, clients)

    # Estimate difficulty
    intel.difficulty = _estimate_difficulty(network, clients)

    # Priority score
    intel.priority_score = _score_target(network, clients)

    return intel


def _recommend_technique(network: Network, clients: List[Client]) -> str:
    """Pick the best attack technique for a target."""

    # WPS unlocked → Pixie-Dust is fastest
    if network.wps_enabled and not network.wps_locked:
        return "wps-pixie"

    high_traffic = [c for c in clients if c.packets_sent > 1000]

    # High-traffic client → targeted deauth is most reliable
    if high_traffic:
        return "deauth-targeted"

    # Any clients → deauth broadcast
    if clients:
        return "deauth-broadcast"

    # No clients → PMKID is the only option (clientless)
    return "pmkid"


def _estimate_difficulty(network: Network, clients: List[Client]) -> str:
    """Estimate capture difficulty: HIGH (easy to crack), MED, LOW (hard)."""

    score = 0

    # Clients make it much easier
    high_traffic = [c for c in clients if c.packets_sent > 1000]
    if high_traffic:
        score += 3
    elif clients:
        score += 2

    # Strong signal helps
    if network.signal_strength > -50:
        score += 2
    elif network.signal_strength > -70:
        score += 1

    # WPS is a shortcut
    if network.wps_enabled and not network.wps_locked:
        score += 2

    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MED"
    return "LOW"


def _score_target(network: Network, clients: List[Client]) -> float:
    """Score a target for priority ordering (higher = attack first)."""

    score = 0.0

    # Clients are the biggest factor
    if clients:
        score += 50
        high_traffic = [c for c in clients if c.packets_sent > 1000]
        score += len(high_traffic) * 20
        score += min(len(clients) * 10, 50)

    # Signal strength (normalize -30 to -90 range)
    if network.signal_strength > -90:
        score += max(0, (90 + network.signal_strength) / 60 * 30)

    # WPS bonus
    if network.wps_enabled and not network.wps_locked:
        score += 25

    # Encryption type
    enc_val = network.encryption.value if hasattr(network.encryption, "value") else ""
    if "WPA2" in enc_val:
        score += 10

    return score
