#!/usr/bin/env python3
"""
Scanner Data Models

Defines data structures for network scanning operations.
All models use dataclasses with type hints for clarity.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class EncryptionType(Enum):
    """WiFi encryption types"""
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
    """WiFi frequency bands"""
    BAND_2_4GHZ = "2.4GHz"
    BAND_5GHZ = "5GHz"
    BAND_6GHZ = "6GHz"


@dataclass
class Network:
    """Represents a discovered WiFi network"""
    bssid: str
    ssid: str
    channel: int
    frequency: int
    signal_strength: int  # in dBm
    encryption: EncryptionType
    cipher: Optional[str] = None
    authentication: Optional[str] = None

    # Extended properties
    manufacturer: Optional[str] = None
    hidden: bool = False
    wps_enabled: bool = False
    wps_locked: bool = False
    wifi_standard: Optional[str] = None  # 802.11n/ac/ax
    band: Optional[WiFiBand] = None

    # Statistics
    beacon_rate: int = 0
    data_packets: int = 0
    total_packets: int = 0

    # Timestamps
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    # Target metadata
    is_target: bool = False
    priority: int = 5  # 1-10 scale
    notes: str = ""

    def __hash__(self):
        return hash(self.bssid)

    def __eq__(self, other):
        if isinstance(other, Network):
            return self.bssid == other.bssid
        return False

    def update_signal(self, new_signal: int):
        """Update signal strength with smoothing"""
        alpha = 0.3  # Smoothing factor
        self.signal_strength = int(
            alpha * new_signal + (1 - alpha) * self.signal_strength
        )
        self.last_seen = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
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
            "notes": self.notes
        }


@dataclass
class Client:
    """Represents a client device connected to a network"""
    mac_address: str
    associated_bssid: Optional[str] = None

    # Device info
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None  # Phone, Laptop, IoT, etc.
    hostname: Optional[str] = None

    # Statistics
    signal_strength: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    data_rate: float = 0.0

    # Probe requests
    probed_ssids: List[str] = field(default_factory=list)

    # Timestamps
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    # Metadata
    is_target: bool = False
    notes: str = ""

    def __hash__(self):
        return hash(self.mac_address)

    def __eq__(self, other):
        if isinstance(other, Client):
            return self.mac_address == other.mac_address
        return False

    def add_probe(self, ssid: str):
        """Add a probed SSID if not already present"""
        if ssid and ssid not in self.probed_ssids:
            self.probed_ssids.append(ssid)
            self.last_seen = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
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
            "probed_ssids": self.probed_ssids,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "is_target": self.is_target,
            "notes": self.notes
        }


@dataclass
class Handshake:
    """Represents a captured WPA/WPA2 handshake"""
    bssid: str
    ssid: str
    client_mac: str

    # File information
    pcap_file: str
    file_size: int

    # Handshake quality
    eapol_packets: int = 0
    m1_present: bool = False
    m2_present: bool = False
    m3_present: bool = False
    m4_present: bool = False
    is_complete: bool = False
    quality_score: float = 0.0  # 0-100

    # Capture metadata
    capture_time: datetime = field(default_factory=datetime.now)
    capture_method: str = "deauth"  # deauth, passive, pmkid
    deauth_count: int = 0
    time_to_capture: float = 0.0  # seconds

    # Cracking status
    cracked: bool = False
    password: Optional[str] = None
    crack_time: Optional[float] = None
    crack_method: Optional[str] = None

    def validate(self) -> bool:
        """Check if handshake has minimum required packets"""
        # Need M1+M2 or M2+M3 or M3+M4 for valid handshake
        valid_combinations = [
            (self.m1_present and self.m2_present),
            (self.m2_present and self.m3_present),
            (self.m3_present and self.m4_present)
        ]
        self.is_complete = any(valid_combinations)

        # Calculate quality score
        packet_score = min(self.eapol_packets * 10, 40)
        completeness_score = sum([
            self.m1_present * 15,
            self.m2_present * 15,
            self.m3_present * 15,
            self.m4_present * 15
        ])
        self.quality_score = min(packet_score + completeness_score, 100)

        return self.is_complete

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "client_mac": self.client_mac,
            "pcap_file": self.pcap_file,
            "file_size": self.file_size,
            "eapol_packets": self.eapol_packets,
            "m1_present": self.m1_present,
            "m2_present": self.m2_present,
            "m3_present": self.m3_present,
            "m4_present": self.m4_present,
            "is_complete": self.is_complete,
            "quality_score": self.quality_score,
            "capture_time": self.capture_time.isoformat(),
            "capture_method": self.capture_method,
            "deauth_count": self.deauth_count,
            "time_to_capture": self.time_to_capture,
            "cracked": self.cracked,
            "password": self.password,
            "crack_time": self.crack_time,
            "crack_method": self.crack_method
        }


@dataclass
class ScanResult:
    """Container for scan results"""
    networks: List[Network] = field(default_factory=list)
    clients: List[Client] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    duration: float = 0.0
    channels_scanned: List[int] = field(default_factory=list)

    def add_network(self, network: Network):
        """Add or update a network"""
        existing = next((n for n in self.networks if n.bssid == network.bssid), None)
        if existing:
            existing.update_signal(network.signal_strength)
            existing.total_packets = network.total_packets
            existing.last_seen = network.last_seen
        else:
            self.networks.append(network)

    def add_client(self, client: Client):
        """Add or update a client"""
        existing = next((c for c in self.clients if c.mac_address == client.mac_address), None)
        if existing:
            existing.signal_strength = client.signal_strength
            existing.packets_sent = client.packets_sent
            existing.packets_received = client.packets_received
            existing.last_seen = client.last_seen
            for ssid in client.probed_ssids:
                existing.add_probe(ssid)
        else:
            self.clients.append(client)

    def get_associated_clients(self, bssid: str) -> List[Client]:
        """Get all clients associated with a specific network"""
        return [c for c in self.clients if c.associated_bssid == bssid]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "networks": [n.to_dict() for n in self.networks],
            "clients": [c.to_dict() for c in self.clients],
            "scan_time": self.scan_time.isoformat(),
            "duration": self.duration,
            "channels_scanned": self.channels_scanned,
            "stats": {
                "total_networks": len(self.networks),
                "total_clients": len(self.clients),
                "open_networks": len([n for n in self.networks if n.encryption == EncryptionType.OPEN]),
                "wps_networks": len([n for n in self.networks if n.wps_enabled]),
                "hidden_networks": len([n for n in self.networks if n.hidden])
            }
        }