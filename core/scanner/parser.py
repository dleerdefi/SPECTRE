#!/usr/bin/env python3
"""
Airodump-ng Output Parser

Parses CSV output from airodump-ng for network and client discovery.
Handles both real-time streaming and batch file processing.
"""

import csv
import re
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, IO
from io import StringIO

from .models import Network, Client, ScanResult, EncryptionType, WiFiBand

logger = logging.getLogger(__name__)


class AirodumpParser:
    """Parses airodump-ng CSV output into structured data"""

    # OUI database for manufacturer lookup (subset for common devices)
    OUI_DATABASE = {
        "00:00:5E": "USC Information Sciences Institute",
        "00:03:93": "Apple",
        "00:09:5B": "Netgear",
        "00:0C:42": "Cisco-Linksys",
        "00:13:10": "Cisco-Linksys",
        "00:1B:11": "D-Link",
        "00:1D:7E": "Cisco-Linksys",
        "00:24:01": "D-Link",
        "00:25:9C": "Cisco-Linksys",
        "00:50:F2": "Microsoft",
        "00:90:4C": "Epigram",
        "08:86:3B": "Belkin",
        "10:FE:ED": "TP-Link",
        "18:A6:F7": "TP-Link",
        "1C:87:2C": "ASUSTek",
        "30:B5:C2": "TP-Link",
        "34:97:F6": "ASUSTek",
        "3C:37:86": "Apple",
        "48:5D:60": "Azurewave (Ralink)",
        "50:C7:BF": "TP-Link",
        "54:27:1E": "AzureWave",
        "58:D5:6E": "D-Link",
        "5C:AA:FD": "Sonos",
        "60:A4:4C": "ASUSTek",
        "64:66:B3": "TP-Link",
        "68:7F:74": "Cisco-Linksys",
        "70:4F:57": "TP-Link",
        "74:DA:38": "Edimax",
        "78:24:AF": "ASUSTek",
        "80:2A:A8": "Ubiquiti",
        "84:16:F9": "TP-Link",
        "90:F6:52": "TP-Link",
        "94:10:3E": "Belkin",
        "98:DA:C4": "ASUS",
        "A0:F3:C1": "TP-Link",
        "A4:2B:B0": "TP-Link",
        "AC:84:C6": "TP-Link",
        "B0:95:8E": "TP-Link",
        "B4:75:0E": "Belkin",
        "C0:4A:00": "TP-Link",
        "C0:C1:C0": "Cisco-Linksys",
        "C4:6E:1F": "TP-Link",
        "C8:3A:35": "Tenda",
        "C8:D3:A3": "D-Link",
        "CC:B2:55": "Cisco",
        "D8:0D:17": "TP-Link",
        "D8:47:32": "TP-Link",
        "DC:FB:48": "Intel Corporate",
        "E4:C6:3D": "Apple",
        "E8:DE:27": "TP-Link",
        "EC:08:6B": "TP-Link",
        "EC:1A:59": "Belkin",
        "F0:9F:C2": "Ubiquiti",
        "F4:EC:38": "TP-Link",
        "F8:1A:67": "TP-Link",
        "FC:EC:DA": "Ubiquiti"
    }

    def __init__(self):
        self.networks: Dict[str, Network] = {}
        self.clients: Dict[str, Client] = {}

    def parse_csv_file(self, filepath: str) -> ScanResult:
        """Parse a complete CSV file from airodump-ng"""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"CSV file not found: {filepath}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return self._parse_csv_content(f.read())

    def parse_csv_stream(self, stream: IO) -> ScanResult:
        """Parse CSV content from a stream"""
        content = stream.read()
        return self._parse_csv_content(content)

    def _parse_csv_content(self, content: str) -> ScanResult:
        """Parse CSV content into structured data"""
        result = ScanResult()

        # Split into sections (networks and clients)
        sections = content.split('\n\n')
        if len(sections) < 2:
            logger.warning("Invalid CSV format - missing sections")
            return result

        # Parse networks section
        networks_section = sections[0]
        self._parse_networks(networks_section, result)

        # Parse clients section if present
        if len(sections) > 1:
            clients_section = sections[1]
            self._parse_clients(clients_section, result)

        return result

    def _parse_networks(self, csv_content: str, result: ScanResult):
        """Parse the networks section of the CSV"""
        reader = csv.reader(StringIO(csv_content))

        # Skip header
        header = next(reader, None)
        if not header:
            return

        for row in reader:
            if len(row) < 14:  # Minimum required fields
                continue

            try:
                network = self._parse_network_row(row)
                if network:
                    result.add_network(network)
            except Exception as e:
                logger.debug(f"Error parsing network row: {e}")
                continue

    def _parse_network_row(self, row: List[str]) -> Optional[Network]:
        """Parse a single network row from CSV"""
        # CSV format: BSSID, First time seen, Last time seen, channel, Speed,
        # Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP,
        # ID-length, ESSID, Key

        bssid = row[0].strip()
        if not self._is_valid_mac(bssid):
            return None

        # Parse basic fields
        channel = self._parse_int(row[3])
        power = self._parse_int(row[8])
        beacons = self._parse_int(row[9])
        privacy = row[5].strip()
        cipher = row[6].strip() if len(row) > 6 else ""
        auth = row[7].strip() if len(row) > 7 else ""
        essid = row[13].strip() if len(row) > 13 else ""

        # Clean up ESSID
        essid = essid.strip('\x00').strip()
        hidden = essid == "" or essid == "<length: 0>"

        # Determine encryption type
        encryption = self._parse_encryption(privacy, cipher, auth)

        # Check for WPS
        wps_enabled = "WPS" in privacy or "WPS" in auth

        # Determine frequency and band
        frequency = self._channel_to_frequency(channel)
        band = self._get_wifi_band(frequency)

        # Get manufacturer from OUI
        manufacturer = self._get_manufacturer(bssid)

        # Parse timestamps
        first_seen = self._parse_timestamp(row[1])
        last_seen = self._parse_timestamp(row[2])

        network = Network(
            bssid=bssid,
            ssid=essid if not hidden else f"<Hidden Network>",
            channel=channel,
            frequency=frequency,
            signal_strength=power,
            encryption=encryption,
            cipher=cipher,
            authentication=auth,
            manufacturer=manufacturer,
            hidden=hidden,
            wps_enabled=wps_enabled,
            band=band,
            beacon_rate=beacons,
            first_seen=first_seen,
            last_seen=last_seen
        )

        return network

    def _parse_clients(self, csv_content: str, result: ScanResult):
        """Parse the clients section of the CSV"""
        reader = csv.reader(StringIO(csv_content))

        # Skip header
        header = next(reader, None)
        if not header:
            return

        for row in reader:
            if len(row) < 7:  # Minimum required fields
                continue

            try:
                client = self._parse_client_row(row)
                if client:
                    result.add_client(client)
            except Exception as e:
                logger.debug(f"Error parsing client row: {e}")
                continue

    def _parse_client_row(self, row: List[str]) -> Optional[Client]:
        """Parse a single client row from CSV"""
        # CSV format: Station MAC, First time seen, Last time seen, Power,
        # # packets, BSSID, Probed ESSIDs

        mac = row[0].strip()
        if not self._is_valid_mac(mac):
            return None

        power = self._parse_int(row[3])
        packets = self._parse_int(row[4])
        bssid = row[5].strip() if len(row) > 5 else ""

        # Parse associated BSSID
        associated_bssid = None
        if self._is_valid_mac(bssid) and bssid != "(not associated)":
            associated_bssid = bssid

        # Parse probed SSIDs
        probed_ssids = []
        if len(row) > 6:
            probes = row[6].strip()
            if probes:
                # Split by comma and clean up
                probed_ssids = [s.strip() for s in probes.split(',') if s.strip()]

        # Get manufacturer from OUI
        manufacturer = self._get_manufacturer(mac)

        # Parse timestamps
        first_seen = self._parse_timestamp(row[1])
        last_seen = self._parse_timestamp(row[2])

        client = Client(
            mac_address=mac,
            associated_bssid=associated_bssid,
            manufacturer=manufacturer,
            signal_strength=power,
            packets_sent=packets,
            probed_ssids=probed_ssids,
            first_seen=first_seen,
            last_seen=last_seen
        )

        return client

    def _parse_encryption(self, privacy: str, cipher: str, auth: str) -> EncryptionType:
        """Determine encryption type from privacy/cipher/auth fields"""
        privacy = privacy.upper()
        cipher = cipher.upper()
        auth = auth.upper()

        if "WPA3" in privacy or "SAE" in auth:
            return EncryptionType.WPA3
        elif "WPA2" in privacy and "WPA" in privacy:
            return EncryptionType.WPA_WPA2
        elif "WPA2" in privacy:
            return EncryptionType.WPA2
        elif "WPA" in privacy:
            return EncryptionType.WPA
        elif "WEP" in privacy:
            return EncryptionType.WEP
        elif "OPN" in privacy or privacy == "":
            return EncryptionType.OPEN
        elif "802.1X" in auth or "MGT" in auth:
            return EncryptionType.ENTERPRISE
        else:
            return EncryptionType.UNKNOWN

    def _channel_to_frequency(self, channel: int) -> int:
        """Convert WiFi channel to frequency in MHz"""
        if channel <= 0:
            return 0
        elif channel <= 14:
            # 2.4 GHz band
            if channel == 14:
                return 2484
            else:
                return 2407 + (channel * 5)
        elif channel >= 36 and channel <= 165:
            # 5 GHz band
            return 5000 + (channel * 5)
        else:
            # 6 GHz band or unknown
            return 5955 + (channel - 1) * 5

    def _get_wifi_band(self, frequency: int) -> Optional[WiFiBand]:
        """Determine WiFi band from frequency"""
        if 2400 <= frequency <= 2500:
            return WiFiBand.BAND_2_4GHZ
        elif 5000 <= frequency <= 5900:
            return WiFiBand.BAND_5GHZ
        elif 5900 <= frequency <= 7200:
            return WiFiBand.BAND_6GHZ
        return None

    def _get_manufacturer(self, mac_address: str) -> Optional[str]:
        """Get manufacturer from MAC address OUI"""
        if not mac_address:
            return None

        # Get first 3 octets (OUI)
        oui = mac_address[:8].upper()
        return self.OUI_DATABASE.get(oui, None)

    def _is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        if not mac:
            return False
        # Simple regex for MAC address validation
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))

    def _parse_int(self, value: str) -> int:
        """Safely parse integer from string"""
        try:
            # Remove any non-numeric characters except minus
            cleaned = re.sub(r'[^\d-]', '', value.strip())
            return int(cleaned) if cleaned else 0
        except (ValueError, AttributeError):
            return 0

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp from airodump-ng format"""
        try:
            # Format: 2024-01-15 14:30:45
            return datetime.strptime(timestamp_str.strip(), "%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            return datetime.now()