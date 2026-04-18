"""Survey and scan domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class EncryptionType(Enum):
    """WiFi encryption types."""

    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA_WPA2 = "WPA/WPA2"
    WPS = "WPS"
    ENTERPRISE = "Enterprise"
    UNKNOWN = "Unknown"


class WiFiBand(Enum):
    """WiFi frequency bands."""

    BAND_2_4GHZ = "2.4GHz"
    BAND_5GHZ = "5GHz"
    BAND_6GHZ = "6GHz"


@dataclass
class Network:
    """Represents a discovered WiFi network."""

    bssid: str
    ssid: str
    channel: int
    frequency: int
    signal_strength: int
    encryption: EncryptionType
    cipher: Optional[str] = None
    authentication: Optional[str] = None
    manufacturer: Optional[str] = None
    hidden: bool = False
    wps_enabled: bool = False
    wps_locked: bool = False
    wifi_standard: Optional[str] = None
    band: Optional[WiFiBand] = None
    beacon_rate: int = 0
    data_packets: int = 0
    total_packets: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_target: bool = False
    priority: int = 5
    notes: str = ""

    def __hash__(self) -> int:
        return hash(self.bssid)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Network) and self.bssid == other.bssid

    def update_signal(self, new_signal: int) -> None:
        """Update signal strength with basic smoothing."""

        alpha = 0.3
        self.signal_strength = int(alpha * new_signal + (1 - alpha) * self.signal_strength)
        self.last_seen = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "signal_strength": self.signal_strength,
            "encryption": self.encryption.value,
            "cipher": self.cipher,
            "authentication": self.authentication,
            "manufacturer": self.manufacturer,
            "hidden": self.hidden,
            "wps_enabled": self.wps_enabled,
            "wps_locked": self.wps_locked,
            "wifi_standard": self.wifi_standard,
            "band": self.band.value if self.band else None,
            "beacon_rate": self.beacon_rate,
            "data_packets": self.data_packets,
            "total_packets": self.total_packets,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "is_target": self.is_target,
            "priority": self.priority,
            "notes": self.notes,
        }


@dataclass
class Client:
    """Represents a client device observed during a survey."""

    mac_address: str
    associated_bssid: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None
    hostname: Optional[str] = None
    signal_strength: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    data_rate: float = 0.0
    probed_ssids: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_target: bool = False
    notes: str = ""

    def __hash__(self) -> int:
        return hash(self.mac_address)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Client) and self.mac_address == other.mac_address

    def add_probe(self, ssid: str) -> None:
        """Track a probed SSID once."""

        if ssid and ssid not in self.probed_ssids:
            self.probed_ssids.append(ssid)
            self.last_seen = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac_address": self.mac_address,
            "associated_bssid": self.associated_bssid,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type,
            "hostname": self.hostname,
            "signal_strength": self.signal_strength,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "data_rate": self.data_rate,
            "probed_ssids": list(self.probed_ssids),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "is_target": self.is_target,
            "notes": self.notes,
        }


@dataclass
class ScanResult:
    """Container for scan results and summary helpers."""

    networks: List[Network] = field(default_factory=list)
    clients: List[Client] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    duration: float = 0.0
    channels_scanned: List[int] = field(default_factory=list)

    def add_network(self, network: Network) -> None:
        """Add a new network or update an existing observation."""

        existing = next((item for item in self.networks if item.bssid == network.bssid), None)
        if existing:
            existing.update_signal(network.signal_strength)
            existing.total_packets = network.total_packets
            existing.last_seen = network.last_seen
            return
        self.networks.append(network)

    def add_client(self, client: Client) -> None:
        """Add a new client or merge a repeat observation."""

        existing = next((item for item in self.clients if item.mac_address == client.mac_address), None)
        if existing:
            existing.signal_strength = client.signal_strength
            existing.packets_sent = client.packets_sent
            existing.packets_received = client.packets_received
            existing.last_seen = client.last_seen
            for ssid in client.probed_ssids:
                existing.add_probe(ssid)
            return
        self.clients.append(client)

    def merge(self, other: "ScanResult") -> None:
        """Merge another ScanResult into this one.

        Deduplicates networks by BSSID and clients by MAC, keeping the
        richer data from each source via add_network/add_client logic.
        """
        for net in other.networks:
            self.add_network(net)
        for client in other.clients:
            self.add_client(client)
        # Extend channel list
        for ch in other.channels_scanned:
            if ch not in self.channels_scanned:
                self.channels_scanned.append(ch)

    def get_associated_clients(self, bssid: str) -> List[Client]:
        """Return clients associated with a specific BSSID."""

        return [client for client in self.clients if client.associated_bssid == bssid]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "networks": [network.to_dict() for network in self.networks],
            "clients": [client.to_dict() for client in self.clients],
            "scan_time": self.scan_time.isoformat(),
            "duration": self.duration,
            "channels_scanned": list(self.channels_scanned),
            "stats": {
                "total_networks": len(self.networks),
                "total_clients": len(self.clients),
                "open_networks": len(
                    [network for network in self.networks if network.encryption == EncryptionType.OPEN]
                ),
                "wps_networks": len([network for network in self.networks if network.wps_enabled]),
                "hidden_networks": len([network for network in self.networks if network.hidden]),
            },
        }


__all__ = ["Client", "EncryptionType", "Network", "ScanResult", "WiFiBand"]

