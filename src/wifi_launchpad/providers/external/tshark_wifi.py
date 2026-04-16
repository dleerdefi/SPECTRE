"""Normalize WiFi observations from pcapng artifacts via tshark."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import subprocess
from typing import Dict, Iterable, Optional, Set

from wifi_launchpad.domain.survey import Client, EncryptionType, Network, ScanResult, WiFiBand

FIELDS = (
    "frame.time_epoch",
    "wlan.bssid",
    "wlan.sa",
    "wlan.ta",
    "wlan.ssid",
    "wlan_radio.channel",
    "radiotap.dbm_antsignal",
    "wlan.fixed.beacon",
    "wlan.fixed.capabilities.privacy",
    "wlan.rsn.version",
    "wlan.rsn.pcs.type",
    "wlan.rsn.akms.type",
    "wlan.wfa.ie.wpa.version",
    "wlan.wfa.ie.wpa.ucs.type",
    "wlan.wfa.ie.wpa.akms.type",
)

CIPHER_TYPES = {2: "TKIP", 4: "CCMP", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
ENTERPRISE_AKMS, PSK_AKMS, SAE_AKMS = {1, 3, 5, 11, 12}, {2, 4, 6, 13}, {8, 9}
TRUTHY = {"1", "true", "yes", "set"}


def parse_capture(path: Path, channels: Optional[Iterable[int]] = None) -> ScanResult:
    """Read a pcapng artifact with tshark and return a normalized scan result."""

    command = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        "wlan",
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
    ]
    for field in FIELDS:
        command.extend(["-e", field])

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError(f"Failed to parse capture with tshark: {exc}") from exc

    return parse_tshark_table(result.stdout, channels=channels)


def parse_tshark_table(stdout: str, channels: Optional[Iterable[int]] = None) -> ScanResult:
    """Parse tshark field output into the shared survey model."""

    allowed_channels = {int(channel) for channel in channels or []}
    observed_channels = set()
    networks: Dict[str, Network] = {}
    clients: Dict[str, Client] = {}
    first_seen: Optional[datetime] = None

    for line in stdout.splitlines():
        if not line.strip():
            continue

        row = _row_from_line(line)
        channel = _parse_int(row["wlan_radio.channel"])
        if allowed_channels and channel and channel not in allowed_channels:
            continue
        if channel:
            observed_channels.add(channel)

        timestamp = _parse_timestamp(row["frame.time_epoch"])
        if first_seen is None or timestamp < first_seen:
            first_seen = timestamp

        bssid = _normalize_mac(row["wlan.bssid"])
        source = _normalize_mac(row["wlan.sa"]) or _normalize_mac(row["wlan.ta"])
        ssid = _decode_ssid(row["wlan.ssid"])
        signal = _parse_int(row["radiotap.dbm_antsignal"], default=-100)

        if bssid and channel:
            _merge_network(networks, row, bssid, ssid, channel, signal, timestamp)
        if source and not _is_multicast(source):
            _merge_client(clients, source, bssid, ssid, signal, timestamp)

    return ScanResult(
        networks=list(networks.values()),
        clients=list(clients.values()),
        scan_time=first_seen or datetime.now(),
        duration=0.0,
        channels_scanned=sorted(observed_channels or allowed_channels),
    )


def _row_from_line(line: str) -> Dict[str, str]:
    values = line.split("\t")
    if len(values) < len(FIELDS):
        values.extend([""] * (len(FIELDS) - len(values)))
    return dict(zip(FIELDS, values))


def _merge_network(
    networks: Dict[str, Network],
    row: Dict[str, str],
    bssid: str,
    ssid: str,
    channel: int,
    signal: int,
    timestamp: datetime,
) -> None:
    encryption, cipher, auth = _parse_security(row)
    hidden = not ssid
    network = networks.get(bssid)
    if not network:
        networks[bssid] = Network(
            bssid=bssid,
            ssid=ssid or "<Hidden Network>",
            channel=channel,
            frequency=_channel_to_frequency(channel),
            signal_strength=signal,
            encryption=encryption,
            cipher=cipher,
            authentication=auth,
            hidden=hidden,
            band=_channel_to_band(channel),
            first_seen=timestamp,
            last_seen=timestamp,
        )
        return

    network.last_seen = timestamp
    network.signal_strength = max(network.signal_strength, signal)
    if ssid and (network.hidden or network.ssid == "<Hidden Network>"):
        network.ssid = ssid
        network.hidden = False
    if network.encryption == EncryptionType.UNKNOWN and encryption != EncryptionType.UNKNOWN:
        network.encryption = encryption
    if cipher and not network.cipher:
        network.cipher = cipher
    if auth and not network.authentication:
        network.authentication = auth


def _merge_client(
    clients: Dict[str, Client],
    source: str,
    bssid: Optional[str],
    ssid: str,
    signal: int,
    timestamp: datetime,
) -> None:
    if source == bssid:
        return

    client = clients.get(source)
    if not client:
        client = Client(
            mac_address=source,
            associated_bssid=bssid,
            signal_strength=signal,
            first_seen=timestamp,
            last_seen=timestamp,
        )
        clients[source] = client
    else:
        client.last_seen = timestamp
        client.signal_strength = max(client.signal_strength, signal)
        if bssid:
            client.associated_bssid = bssid

    if ssid and (not bssid or source != bssid):
        client.add_probe(ssid)


def _parse_security(row: Dict[str, str]) -> tuple[EncryptionType, str, str]:
    privacy = row["wlan.fixed.capabilities.privacy"].strip().lower() in TRUTHY
    rsn = bool(row["wlan.rsn.version"].strip())
    wpa = bool(row["wlan.wfa.ie.wpa.version"].strip())
    beacon_present = bool(row["wlan.fixed.beacon"].strip())

    rsn_akms = _parse_int_set(row["wlan.rsn.akms.type"])
    wpa_akms = _parse_int_set(row["wlan.wfa.ie.wpa.akms.type"])
    cipher_names = sorted(
        {
            *(CIPHER_TYPES.get(value, "") for value in _parse_int_set(row["wlan.rsn.pcs.type"])),
            *(CIPHER_TYPES.get(value, "") for value in _parse_int_set(row["wlan.wfa.ie.wpa.ucs.type"])),
        }
        - {""}
    )

    auth_names = []
    all_akms = rsn_akms | wpa_akms
    if all_akms & SAE_AKMS:
        auth_names.append("SAE")
    if all_akms & PSK_AKMS:
        auth_names.append("PSK")
    if all_akms & ENTERPRISE_AKMS:
        auth_names.append("MGT")

    if rsn and all_akms & SAE_AKMS:
        return EncryptionType.WPA3, " ".join(cipher_names), " ".join(auth_names)
    if (rsn_akms & ENTERPRISE_AKMS) and not (rsn_akms & PSK_AKMS):
        return EncryptionType.ENTERPRISE, " ".join(cipher_names), " ".join(auth_names or ["MGT"])
    if rsn and wpa:
        return EncryptionType.WPA_WPA2, " ".join(cipher_names), " ".join(auth_names)
    if rsn:
        return EncryptionType.WPA2, " ".join(cipher_names), " ".join(auth_names)
    if wpa:
        return EncryptionType.WPA, " ".join(cipher_names), " ".join(auth_names)
    if privacy:
        return EncryptionType.WEP, "", ""
    if beacon_present:
        return EncryptionType.OPEN, "", ""
    return EncryptionType.UNKNOWN, "", ""


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromtimestamp(float(value))
    except (TypeError, ValueError, OSError):
        return datetime.now()


def _parse_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value.split(",")[0]))  # take first of comma-aggregated values
    except (TypeError, ValueError):
        return default


def _parse_int_set(value: str) -> Set[int]:
    numbers = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            numbers.add(int(item))
        except ValueError:
            continue
    return numbers


def _normalize_mac(value: str) -> Optional[str]:
    value = value.strip().upper()
    return value if value and value != "FF:FF:FF:FF:FF:FF" else None


def _decode_ssid(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    raw = value.replace(":", "")  # handle both "aa:bb:cc" and "aabbcc" hex formats
    if raw and all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) >= 2 and len(raw) % 2 == 0:
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", errors="ignore").strip("\x00")
            if decoded and decoded.isprintable():
                return decoded
        except ValueError:
            pass
    return value


def _channel_to_frequency(channel: int) -> int:
    if channel <= 14:
        return 2407 + channel * 5
    return 5000 + channel * 5 if channel >= 1 else 0


def _channel_to_band(channel: int) -> Optional[WiFiBand]:
    if 1 <= channel <= 14:
        return WiFiBand.BAND_2_4GHZ
    if 32 <= channel <= 177:
        return WiFiBand.BAND_5GHZ
    if channel >= 181:
        return WiFiBand.BAND_6GHZ
    return None


def _is_multicast(mac_address: str) -> bool:
    return bool(int(mac_address.split(":", 1)[0], 16) & 1)


__all__ = ["parse_capture", "parse_tshark_table"]
