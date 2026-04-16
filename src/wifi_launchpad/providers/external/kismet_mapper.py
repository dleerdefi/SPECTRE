"""Map Kismet device JSON blobs to wifi_launchpad domain models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

from wifi_launchpad.domain.survey import Client, EncryptionType, Network, ScanResult, WiFiBand

# Kismet device type strings
AP_TYPES = {"Wi-Fi AP"}
CLIENT_TYPES = {"Wi-Fi Client", "Wi-Fi Bridged", "Wi-Fi Device"}

# Encryption token mapping
_CIPHER_TOKENS = {"AES-CCM": "CCMP", "AES-CCMP": "CCMP", "TKIP": "TKIP", "AES-GCMP": "GCMP",
                  "GCMP-256": "GCMP-256", "CCMP-256": "CCMP-256", "CCMP": "CCMP", "GCMP": "GCMP"}
_AUTH_TOKENS = {"PSK": "PSK", "SAE": "SAE", "EAP": "MGT", "OWE": "OWE"}


def map_devices_to_scan_result(
    devices: List[Dict[str, Any]],
    channels: Optional[Iterable[int]] = None,
) -> ScanResult:
    """Convert a list of Kismet device dicts to a ScanResult."""
    allowed = {int(ch) for ch in channels} if channels else set()
    networks: List[Network] = []
    clients: List[Client] = []
    observed_channels: Set[int] = set()

    for dev in devices:
        dev_type = dev.get("type", "")
        if dev_type in AP_TYPES:
            net = _map_network(dev)
            if net is None:
                continue
            if allowed and net.channel not in allowed:
                continue
            if net.channel:
                observed_channels.add(net.channel)
            networks.append(net)
        elif dev_type in CLIENT_TYPES:
            client = _map_client(dev)
            if client is not None:
                clients.append(client)

    first_times = [dev.get("first_time", 0) for dev in devices if dev.get("first_time")]
    scan_time = datetime.fromtimestamp(min(first_times)) if first_times else datetime.now()

    return ScanResult(
        networks=networks,
        clients=clients,
        scan_time=scan_time,
        duration=0.0,
        channels_scanned=sorted(observed_channels or allowed),
    )


def _map_network(dev: Dict[str, Any]) -> Optional[Network]:
    """Map a Kismet AP device to a Network domain object."""
    blob = dev.get("device", {})
    mac = dev.get("devmac", blob.get("kismet.device.base.macaddr", ""))
    if not mac:
        return None

    dot11 = blob.get("dot11.device", {})
    ssid_map = dot11.get("dot11.device.advertised_ssid_map", [])
    ssid_record = ssid_map[0] if ssid_map else {}

    ssid = ssid_record.get("dot11.advertisedssid.ssid", "") or blob.get("kismet.device.base.name", "")
    cloaked = ssid_record.get("dot11.advertisedssid.cloaked", 0)
    hidden = bool(cloaked) or not ssid

    channel_str = blob.get("kismet.device.base.channel", "")
    channel = _parse_channel(channel_str)
    frequency = blob.get("kismet.device.base.frequency", 0)
    if frequency:
        frequency = frequency // 1000  # kHz → MHz

    signal_data = blob.get("kismet.device.base.signal", {})
    signal = signal_data.get("kismet.common.signal.last_signal", dev.get("strongest_signal", -100))

    crypt_str = blob.get("kismet.device.base.crypt", "")
    encryption, cipher, auth = _parse_kismet_crypt(crypt_str)

    packets = blob.get("kismet.device.base.packets.total", 0)
    beacon_rate = ssid_record.get("dot11.advertisedssid.beaconrate", 0)
    ht_mode = ssid_record.get("dot11.advertisedssid.ht_mode", "")
    manuf = blob.get("kismet.device.base.manuf", "")

    first_time = dev.get("first_time") or blob.get("kismet.device.base.first_time", 0)
    last_time = dev.get("last_time") or blob.get("kismet.device.base.last_time", 0)

    return Network(
        bssid=mac.upper(),
        ssid=ssid if ssid else "<Hidden Network>",
        channel=channel,
        frequency=frequency,
        signal_strength=signal or -100,
        encryption=encryption,
        cipher=cipher,
        authentication=auth,
        manufacturer=manuf or None,
        hidden=hidden,
        band=_channel_to_band(channel),
        beacon_rate=beacon_rate,
        total_packets=packets,
        wifi_standard=ht_mode or None,
        first_seen=datetime.fromtimestamp(first_time) if first_time else datetime.now(),
        last_seen=datetime.fromtimestamp(last_time) if last_time else datetime.now(),
    )


def _map_client(dev: Dict[str, Any]) -> Optional[Client]:
    """Map a Kismet client device to a Client domain object."""
    blob = dev.get("device", {})
    mac = dev.get("devmac", blob.get("kismet.device.base.macaddr", ""))
    if not mac:
        return None

    dot11 = blob.get("dot11.device", {})
    associated_bssid = dot11.get("dot11.device.last_bssid")

    signal_data = blob.get("kismet.device.base.signal", {})
    signal = signal_data.get("kismet.common.signal.last_signal", dev.get("strongest_signal", -100))

    packets_total = blob.get("kismet.device.base.packets.total", 0)
    packets_tx = blob.get("kismet.device.base.packets.tx_total", 0)
    packets_rx = blob.get("kismet.device.base.packets.rx_total", 0)

    probed_map = dot11.get("dot11.device.probed_ssid_map", [])
    probed_ssids = []
    for probe in probed_map:
        ssid = probe.get("dot11.probedssid.ssid", "")
        if ssid:
            probed_ssids.append(ssid)

    manuf = blob.get("kismet.device.base.manuf", "")
    first_time = dev.get("first_time") or blob.get("kismet.device.base.first_time", 0)
    last_time = dev.get("last_time") or blob.get("kismet.device.base.last_time", 0)

    return Client(
        mac_address=mac.upper(),
        associated_bssid=associated_bssid.upper() if associated_bssid else None,
        manufacturer=manuf or None,
        signal_strength=signal or -100,
        packets_sent=packets_tx or packets_total,
        packets_received=packets_rx,
        probed_ssids=probed_ssids,
        first_seen=datetime.fromtimestamp(first_time) if first_time else datetime.now(),
        last_seen=datetime.fromtimestamp(last_time) if last_time else datetime.now(),
    )


def _parse_kismet_crypt(crypt: str) -> tuple[EncryptionType, str, str]:
    """Parse Kismet's crypt string into (EncryptionType, cipher, auth).

    Examples: "WPA3 WPA3-PSK WPA3-SAE AES-CCMP", "WPA2-PSK TKIP AES-CCMP", "None"
    """
    if not crypt or crypt.lower() == "none":
        return EncryptionType.OPEN, "", ""

    tokens = crypt.split()
    ciphers: List[str] = []
    auths: List[str] = []
    has_wpa3 = False
    has_wpa2 = False
    has_wpa = False
    has_enterprise = False

    for token in tokens:
        upper = token.upper()
        if upper in _CIPHER_TOKENS:
            ciphers.append(_CIPHER_TOKENS[upper])
        for auth_key, auth_val in _AUTH_TOKENS.items():
            if auth_key in upper:
                if auth_val not in auths:
                    auths.append(auth_val)
        if "EAP" in upper or "MGT" in upper:
            has_enterprise = True
        if "WPA3" in upper:
            has_wpa3 = True
        elif "WPA2" in upper:
            has_wpa2 = True
        elif "WPA" in upper:
            has_wpa = True

    cipher_str = " ".join(sorted(set(ciphers)))
    auth_str = " ".join(auths)

    if has_enterprise:
        return EncryptionType.ENTERPRISE, cipher_str, auth_str or "MGT"
    if has_wpa3:
        return EncryptionType.WPA3, cipher_str, auth_str
    if has_wpa2 and has_wpa:
        return EncryptionType.WPA_WPA2, cipher_str, auth_str
    if has_wpa2:
        return EncryptionType.WPA2, cipher_str, auth_str
    if has_wpa:
        return EncryptionType.WPA, cipher_str, auth_str
    if "WEP" in crypt.upper():
        return EncryptionType.WEP, "", ""
    return EncryptionType.UNKNOWN, cipher_str, auth_str


def _parse_channel(value: str) -> int:
    """Parse channel string to int, handling Kismet's format."""
    if not value:
        return 0
    try:
        return int(value.split(",")[0].strip())
    except (ValueError, IndexError):
        return 0


def _channel_to_band(channel: int) -> Optional[WiFiBand]:
    if 1 <= channel <= 14:
        return WiFiBand.BAND_2_4GHZ
    if 32 <= channel <= 177:
        return WiFiBand.BAND_5GHZ
    if channel >= 181:
        return WiFiBand.BAND_6GHZ
    return None


__all__ = ["map_devices_to_scan_result"]
