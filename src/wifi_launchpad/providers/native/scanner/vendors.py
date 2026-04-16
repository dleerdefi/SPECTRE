"""Vendor and device-type lookup helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Dict, Optional

from wifi_launchpad.app.settings import get_settings

from .oui_parts import OUI_DATA_PARTS

logger = logging.getLogger(__name__)


class OUIDatabase:
    """MAC address vendor lookup database."""

    COMMON_OUIS: Dict[str, str] = {
        key: value for part in OUI_DATA_PARTS for key, value in part.items()
    }

    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = cache_file
        self.extended_db: Dict[str, str] = {}
        if cache_file and cache_file.exists():
            self._load_cache()

    def lookup(self, mac_address: str) -> Optional[str]:
        """Look up the vendor for a MAC address."""

        mac = self._normalize_mac(mac_address)
        if not mac:
            return None
        oui = mac[:8].upper()
        return self.COMMON_OUIS.get(oui) or self.extended_db.get(oui)

    def get_device_type(self, mac_address: str, vendor: Optional[str] = None) -> str:
        """Guess a device category from the MAC address and vendor."""

        vendor_name = vendor or self.lookup(mac_address)
        if not vendor_name:
            return "Unknown"

        vendor_lower = vendor_name.lower()
        if any(term in vendor_lower for term in ["tp-link", "netgear", "asus", "linksys", "cisco", "d-link", "belkin", "ubiquiti", "mikrotik", "aruba"]):
            return "Router/AP"
        if any(term in vendor_lower for term in ["apple", "samsung", "oneplus", "xiaomi", "huawei", "oppo", "vivo"]):
            return "Phone/Tablet"
        if any(term in vendor_lower for term in ["intel", "dell", "hp", "lenovo", "acer", "microsoft surface"]):
            return "Laptop/PC"
        if any(term in vendor_lower for term in ["playstation", "xbox", "nintendo"]):
            return "Gaming Console"
        if any(term in vendor_lower for term in ["nest", "ring", "sonos", "philips lighting", "amazon echo", "google home", "chromecast", "kindle", "fire"]):
            return "IoT/Smart Home"
        if any(term in vendor_lower for term in ["lg electronics", "samsung electronics", "sony", "roku", "vizio"]):
            return "Smart TV"
        return "Other"

    def update_cache(self, oui_data: Dict[str, str]) -> None:
        """Update and persist the extended cache."""

        self.extended_db.update(oui_data)
        if not self.cache_file:
            return
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self.extended_db, indent=2), encoding="utf-8")
            logger.info("Updated OUI cache with %s entries", len(oui_data))
        except OSError as exc:
            logger.error("Failed to save OUI cache: %s", exc)

    def _normalize_mac(self, mac: str) -> Optional[str]:
        mac = re.sub(r"[:.\-]", "", mac.upper())
        if len(mac) != 12 or not re.match(r"^[0-9A-F]{12}$", mac):
            return None
        return ":".join(mac[index:index + 2] for index in range(0, 12, 2))

    def _load_cache(self) -> None:
        try:
            self.extended_db = json.loads(self.cache_file.read_text(encoding="utf-8"))
            logger.info("Loaded %s OUI entries from cache", len(self.extended_db))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load OUI cache: %s", exc)


_oui_db: Optional[OUIDatabase] = None


def get_oui_database() -> OUIDatabase:
    """Get the shared OUI database instance."""

    global _oui_db
    if _oui_db is None:
        cache_path = get_settings().oui_cache_file
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        _oui_db = OUIDatabase(cache_path)
    return _oui_db


def lookup_vendor(mac_address: str) -> Optional[str]:
    """Quick vendor lookup for a MAC address."""

    return get_oui_database().lookup(mac_address)


def get_device_type(mac_address: str) -> str:
    """Guess a device type for a MAC address."""

    return get_oui_database().get_device_type(mac_address)
