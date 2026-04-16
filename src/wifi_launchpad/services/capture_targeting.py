"""Helpers for selecting practical capture targets."""

from typing import Dict, List

from wifi_launchpad.domain.survey import EncryptionType, Network, ScanResult


def is_capture_candidate(network: Network) -> bool:
    """Return whether the network is a sensible handshake-capture candidate."""

    if network.encryption in {EncryptionType.OPEN, EncryptionType.ENTERPRISE, EncryptionType.WPA3}:
        return False
    return network.signal_strength < 0 and network.channel > 0


def select_best_target(scan_results: ScanResult) -> Network | None:
    """Pick the most practical capture target from a survey result."""

    candidates = []
    for network in scan_results.networks:
        if not is_capture_candidate(network):
            continue

        score = 0.0
        clients = scan_results.get_associated_clients(network.bssid)
        if clients:
            score += 50 + (len(clients) * 10)
        if network.signal_strength > -90:
            score += (90 + network.signal_strength) / 60 * 30
        if "WPA2" in network.encryption.value:
            score += 20
        elif "WPA" in network.encryption.value:
            score += 15
        if not network.hidden:
            score += 10
        candidates.append((network, score))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[1], reverse=True)
    return candidates[0][0]


def categorize_targets(scan_results: ScanResult) -> Dict[str, List[Network]]:
    """Sort scanned networks into categories by crackability."""

    categories: Dict[str, List[Network]] = {
        "crackable": [],  # WPA/WPA2 — standard attack chain
        "wep": [],        # WEP — fast statistical crack, no hashcat needed
        "wpa3": [],       # WPA3-SAE — not currently crackable
        "open": [],       # Open — no encryption, nothing to crack
        "enterprise": [], # 802.1X/EAP — separate attack surface
        "skip": [],       # Invalid signal/channel or unknown
    }

    for network in scan_results.networks:
        enc = network.encryption
        # Skip hidden/unnamed networks — can't meaningfully target them
        if network.hidden or not network.ssid or network.ssid.startswith("<"):
            categories["skip"].append(network)
            continue
        if network.signal_strength >= 0 or network.channel <= 0:
            categories["skip"].append(network)
        elif enc == EncryptionType.OPEN:
            categories["open"].append(network)
        elif enc == EncryptionType.WPA3:
            categories["wpa3"].append(network)
        elif enc == EncryptionType.WEP:
            categories["wep"].append(network)
        elif enc == EncryptionType.ENTERPRISE:
            categories["enterprise"].append(network)
        elif enc in {EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA_WPA2}:
            categories["crackable"].append(network)
        else:
            categories["skip"].append(network)

    # Sort crackable by score (best targets first)
    def _score(net: Network) -> float:
        s = 0.0
        clients = scan_results.get_associated_clients(net.bssid)
        if clients:
            s += 50 + len(clients) * 10
        if net.signal_strength > -90:
            s += (90 + net.signal_strength) / 60 * 30
        if "WPA2" in net.encryption.value:
            s += 20
        if not net.hidden:
            s += 10
        return s

    categories["crackable"].sort(key=_score, reverse=True)

    return categories
