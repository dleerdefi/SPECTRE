"""Shared helpers for scanner CSV parsing."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Optional

from wifi_launchpad.domain.survey import WiFiBand


def is_valid_mac(mac: str) -> bool:
    """Validate a MAC address string."""

    return bool(mac and re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))


def parse_int(value: str) -> int:
    """Safely parse an integer from noisy CSV text."""

    try:
        cleaned = re.sub(r"[^\d-]", "", value.strip())
        return int(cleaned) if cleaned else 0
    except (AttributeError, ValueError):
        return 0


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse an airodump timestamp or fall back to now."""

    try:
        return datetime.strptime(timestamp_str.strip(), "%Y-%m-%d %H:%M:%S")
    except (AttributeError, ValueError):
        return datetime.now()


def channel_to_frequency(channel: int) -> int:
    """Convert a WiFi channel number to frequency."""

    if channel <= 0:
        return 0
    if channel <= 14:
        return 2484 if channel == 14 else 2407 + (channel * 5)
    if 36 <= channel <= 165:
        return 5000 + (channel * 5)
    return 5955 + (channel - 1) * 5


def wifi_band_for_frequency(frequency: int) -> Optional[WiFiBand]:
    """Return the WiFi band for a frequency."""

    if 2400 <= frequency <= 2500:
        return WiFiBand.BAND_2_4GHZ
    if 5000 <= frequency <= 5900:
        return WiFiBand.BAND_5GHZ
    if 5900 <= frequency <= 7200:
        return WiFiBand.BAND_6GHZ
    return None

