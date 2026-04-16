"""Capture workflow data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class CaptureStatus(Enum):
    """Capture operation state."""

    IDLE = "idle"
    CAPTURING = "capturing"
    DEAUTHING = "deauthing"
    VALIDATING = "validating"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class CaptureConfig:
    """Configuration for handshake capture."""

    target_bssid: str
    target_channel: int
    target_ssid: Optional[str] = None
    capture_timeout: int = 300
    write_interval: int = 2
    deauth_count: int = 5
    deauth_interval: int = 10
    deauth_client: Optional[str] = None
    require_full_handshake: bool = False
    min_quality_score: float = 60.0
    output_dir: Optional[str] = None
    save_raw_pcap: bool = True


class HandshakeType(Enum):
    """Types of handshake captures."""

    FULL = "full"
    PARTIAL = "partial"
    PMKID = "pmkid"
    INVALID = "invalid"


@dataclass
class ValidationResult:
    """Result of handshake validation."""

    is_valid: bool
    handshake_type: HandshakeType
    quality_score: float
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    has_pmkid: bool = False
    ap_mac: Optional[str] = None
    client_mac: Optional[str] = None
    ssid: Optional[str] = None
    total_packets: int = 0
    eapol_packets: int = 0
    beacon_packets: int = 0
    signal_quality: float = 0.0
    timing_quality: float = 0.0
    completeness: float = 0.0
    validation_messages: List[str] = field(default_factory=list)


class DeauthStrategy(Enum):
    """Deauthentication strategies."""

    BROADCAST = "broadcast"
    TARGETED = "targeted"
    SEQUENTIAL = "sequential"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"


@dataclass
class DeauthConfig:
    """Configuration for deauth bursts."""

    strategy: DeauthStrategy = DeauthStrategy.BROADCAST
    packet_count: int = 10
    burst_count: int = 5
    burst_interval: float = 5.0
    max_packets_per_second: int = 100
    cooldown_period: float = 10.0
    prioritize_active_clients: bool = True
    skip_broadcast_if_clients: bool = True
    randomize_timing: bool = False
    vary_packet_count: bool = False

