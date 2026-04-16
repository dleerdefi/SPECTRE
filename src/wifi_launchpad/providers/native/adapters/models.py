"""Adapter data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class WifiAdapter:
    """Represents a WiFi adapter and its operator-relevant metadata."""

    interface: str
    mac_address: str
    phy: str
    driver: Optional[str] = None
    chipset: Optional[str] = None
    usb_id: Optional[str] = None
    monitor_mode: bool = False
    packet_injection: bool = False
    frequency_bands: List[str] = field(default_factory=list)
    supported_modes: List[str] = field(default_factory=list)
    current_mode: str = "managed"
    current_channel: Optional[int] = None
    tx_power: Optional[float] = None
    assigned_role: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.interface} ({self.chipset or 'Unknown'}) - {self.assigned_role or 'No role'}"

