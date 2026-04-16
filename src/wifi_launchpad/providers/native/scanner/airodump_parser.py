"""Airodump-ng CSV parser."""

from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
import logging
from pathlib import Path
from typing import Dict, IO, List, Optional

from wifi_launchpad.domain.survey import Client, EncryptionType, Network, ScanResult

from .parser_helpers import channel_to_frequency, is_valid_mac, parse_int, parse_timestamp, wifi_band_for_frequency
from .vendors import get_device_type, lookup_vendor

logger = logging.getLogger(__name__)


class AirodumpParser:
    """Parse airodump-ng CSV output into structured survey data."""

    OUI_DATABASE = {
        "00:03:93": "Apple",
        "00:09:5B": "Netgear",
        "00:0C:42": "Cisco-Linksys",
        "00:13:10": "Cisco-Linksys",
        "00:1B:11": "D-Link",
        "00:24:01": "D-Link",
        "08:86:3B": "Belkin",
        "10:FE:ED": "TP-Link",
        "1C:87:2C": "ASUSTek",
        "30:B5:C2": "TP-Link",
        "3C:37:86": "Apple",
        "48:5D:60": "MediaTek/Ralink",
        "50:C7:BF": "TP-Link",
        "58:D5:6E": "D-Link",
        "80:2A:A8": "Ubiquiti",
        "CC:B2:55": "Cisco",
        "DC:FB:48": "Intel",
        "E4:C6:3D": "Apple",
        "FC:EC:DA": "Ubiquiti",
    }

    def parse_csv_file(self, filepath: str) -> ScanResult:
        """Parse an airodump CSV file from disk."""

        csv_path = Path(filepath)
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        return self._parse_csv_content(csv_path.read_text(encoding="utf-8", errors="ignore"))

    def parse_csv_stream(self, stream: IO) -> ScanResult:
        """Parse CSV content from a file-like object."""

        return self._parse_csv_content(stream.read())

    def _parse_csv_content(self, content: str) -> ScanResult:
        result = ScanResult()
        cleaned = content.strip().replace("\r", "")
        networks_section, clients_section = self._split_sections(cleaned)
        if networks_section:
            self._parse_networks(networks_section, result)
        if clients_section:
            self._parse_clients(clients_section, result)
        return result

    def _split_sections(self, content: str) -> tuple[str, str]:
        station_marker = "Station MAC"
        if station_marker in content:
            networks_section, station_suffix = content.split(station_marker, 1)
            return networks_section.strip(), (station_marker + station_suffix).strip()
        sections = content.split("\n\n")
        networks_section = sections[0].strip() if sections else ""
        clients_section = sections[1].strip() if len(sections) > 1 else ""
        return networks_section, clients_section

    def _parse_networks(self, csv_content: str, result: ScanResult) -> None:
        reader = csv.reader(StringIO(csv_content))
        if not next(reader, None):
            return
        for row in reader:
            if not row or len(row) < 15:
                continue
            if row[0].strip().lower() == "station mac":
                break
            try:
                network = self._parse_network_row(row)
            except Exception as exc:
                logger.debug("Error parsing network row: %s", exc)
                continue
            if network:
                result.add_network(network)

    def _parse_network_row(self, row: List[str]) -> Optional[Network]:
        bssid = row[0].strip()
        if len(row) < 15 or not is_valid_mac(bssid):
            return None

        channel = parse_int(row[3])
        signal_strength = parse_int(row[8])
        beacon_rate = parse_int(row[9])
        privacy = row[5].strip() if len(row) > 5 else ""
        cipher = row[6].strip() if len(row) > 6 else ""
        auth = row[7].strip() if len(row) > 7 else ""
        essid = (row[13].strip() if len(row) > 13 else "").strip("\x00").strip()
        hidden = essid == "" or essid == "<length: 0>"
        if channel <= 0 or signal_strength == -1:
            return None
        if hidden and beacon_rate <= 0 and not cipher and not auth:
            return None
        frequency = channel_to_frequency(channel)
        manufacturer = lookup_vendor(bssid) or self.OUI_DATABASE.get(bssid[:8].upper())

        return Network(
            bssid=bssid,
            ssid=essid if not hidden else "<Hidden Network>",
            channel=channel,
            frequency=frequency,
            signal_strength=signal_strength,
            encryption=self._parse_encryption(privacy, cipher, auth),
            cipher=cipher,
            authentication=auth,
            manufacturer=manufacturer,
            hidden=hidden,
            wps_enabled="WPS" in privacy.upper() or "WPS" in auth.upper(),
            band=wifi_band_for_frequency(frequency),
            beacon_rate=beacon_rate,
            first_seen=parse_timestamp(row[1]),
            last_seen=parse_timestamp(row[2]),
        )

    def _parse_clients(self, csv_content: str, result: ScanResult) -> None:
        reader = csv.reader(StringIO(csv_content))
        if not next(reader, None):
            return
        for row in reader:
            if len(row) < 7:
                continue
            try:
                client = self._parse_client_row(row)
            except Exception as exc:
                logger.debug("Error parsing client row: %s", exc)
                continue
            if client:
                result.add_client(client)

    def _parse_client_row(self, row: List[str]) -> Optional[Client]:
        mac = row[0].strip()
        if not is_valid_mac(mac):
            return None
        associated_bssid = row[5].strip() if len(row) > 5 else ""
        signal_strength = parse_int(row[3])
        if associated_bssid == "(not associated)" or not is_valid_mac(associated_bssid):
            associated_bssid = None
        if signal_strength == -1:
            return None
        if associated_bssid and associated_bssid.lower() == mac.lower():
            return None
        manufacturer = lookup_vendor(mac) or self.OUI_DATABASE.get(mac[:8].upper())
        return Client(
            mac_address=mac,
            associated_bssid=associated_bssid,
            manufacturer=manufacturer,
            device_type=get_device_type(mac) if manufacturer else None,
            signal_strength=signal_strength,
            packets_sent=parse_int(row[4]),
            probed_ssids=[probe.strip() for probe in row[6:] if probe.strip()],
            first_seen=parse_timestamp(row[1]),
            last_seen=parse_timestamp(row[2]),
        )

    def _parse_encryption(self, privacy: str, cipher: str, auth: str) -> EncryptionType:
        """Determine the best-fit encryption type from CSV fields."""

        privacy_tokens = set(privacy.upper().replace("/", " ").split())
        auth_tokens = set(auth.upper().replace("/", " ").split())
        if "802.1X" in auth_tokens or "MGT" in auth_tokens:
            return EncryptionType.ENTERPRISE
        if "WPA3" in privacy_tokens or "SAE" in auth_tokens:
            return EncryptionType.WPA3
        if "WPA2" in privacy_tokens and "WPA" in privacy_tokens:
            return EncryptionType.WPA_WPA2
        if "WPA2" in privacy_tokens:
            return EncryptionType.WPA2
        if "WPA" in privacy_tokens:
            return EncryptionType.WPA
        if "WEP" in privacy_tokens:
            return EncryptionType.WEP
        if "OPN" in privacy_tokens or not privacy_tokens:
            return EncryptionType.OPEN
        return EncryptionType.UNKNOWN

    def _channel_to_frequency(self, channel: int) -> int:
        """Compatibility wrapper around the shared channel helper."""

        return channel_to_frequency(channel)

    def _get_wifi_band(self, frequency: int):
        """Compatibility wrapper around the shared band helper."""

        return wifi_band_for_frequency(frequency)

    def _get_manufacturer(self, mac_address: str) -> Optional[str]:
        """Compatibility lookup for legacy callers."""

        return lookup_vendor(mac_address) or self.OUI_DATABASE.get(mac_address[:8].upper())

    def _is_valid_mac(self, mac: str) -> bool:
        """Compatibility wrapper around the shared MAC validator."""

        return is_valid_mac(mac)

    def _parse_int(self, value: str) -> int:
        """Compatibility wrapper around the shared integer parser."""

        return parse_int(value)

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Compatibility wrapper around the shared timestamp parser."""

        return parse_timestamp(timestamp_str)
