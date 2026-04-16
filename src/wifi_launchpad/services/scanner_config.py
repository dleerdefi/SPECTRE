"""Configuration types for the packaged scanner service."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class ScanMode(Enum):
    """Scanning modes."""

    DISCOVERY = "discovery"
    TARGETED = "targeted"
    MONITOR = "monitor"
    RECON = "recon"


@dataclass
class ScanConfig:
    """Runtime scan configuration."""

    mode: ScanMode = ScanMode.DISCOVERY
    channels: Optional[List[int]] = None
    target_bssid: Optional[str] = None
    target_ssid: Optional[str] = None
    duration: Optional[int] = None
    channel_dwell_time: float = 2.0
    write_interval: int = 5
    enable_database: bool = False
    enable_alerts: bool = True

