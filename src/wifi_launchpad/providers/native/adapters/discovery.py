"""Low-level adapter discovery helpers."""

from __future__ import annotations

import logging
from pathlib import Path
import re
import subprocess
from typing import List, Optional

from .models import WifiAdapter

logger = logging.getLogger(__name__)

USB_CHIPSET_MAP = {
    "0bda:8812": "RTL8812AU",
    "0bda:8813": "RTL8814AU",
    "0e8d:7961": "MT7921U",
    "148f:3070": "RT3070",
    "148f:3072": "RT3072",
    "0cf3:9271": "AR9271",
}

DRIVER_CHIPSET_MAP = {
    "88XXau": "RTL8812AU",
    "8812au": "RTL8812AU",
    "8814au": "RTL8814AU",
    "mt7921u": "MT7921U",
    "mt76x2u": "MT7612U",
    "rt2800usb": "RT2800",
    "ath9k_htc": "AR9271",
    "ath9k": "AR9xxx",
    "ath10k": "QCA9xxx",
    "ath11k": "QCA6xxx",
    "iwlwifi": "Intel",
}


def get_wireless_interfaces() -> List[str]:
    """Return wireless interfaces reported by `iw dev`."""

    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        logger.debug("Failed to get interfaces: %s", exc)
        return []

    interfaces = []
    for line in result.stdout.splitlines():
        if "Interface" in line:
            interfaces.append(line.split("Interface", 1)[1].strip())

    return interfaces


def load_adapter(interface: str) -> Optional[WifiAdapter]:
    """Build a `WifiAdapter` from kernel and sysfs metadata."""

    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        logger.error("Failed to get info for %s: %s", interface, exc)
        return None

    adapter = WifiAdapter(interface=interface, mac_address="", phy="")
    for line in result.stdout.splitlines():
        if "addr" in line:
            adapter.mac_address = line.split("addr", 1)[1].strip()
        elif "wiphy" in line:
            adapter.phy = f"phy{line.split('wiphy', 1)[1].strip()}"
        elif "type" in line:
            adapter.current_mode = line.split("type", 1)[1].strip()
        elif "channel" in line:
            match = re.search(r"channel (\d+)", line)
            if match:
                adapter.current_channel = int(match.group(1))
        elif "txpower" in line:
            match = re.search(r"(\d+\.\d+) dBm", line)
            if match:
                adapter.tx_power = float(match.group(1))

    driver_path = Path(f"/sys/class/net/{interface}/device/driver")
    if driver_path.exists():
        adapter.driver = driver_path.resolve().name

    adapter.usb_id = get_usb_id(interface)
    adapter.chipset = detect_chipset(adapter.driver, adapter.usb_id)
    return adapter


def get_usb_id(interface: str) -> Optional[str]:
    """Return the USB vendor/product id for a USB-backed interface."""

    try:
        device_path = Path(f"/sys/class/net/{interface}/device")
        vendor_path = device_path / "idVendor"
        product_path = device_path / "idProduct"
        if vendor_path.exists() and product_path.exists():
            vendor = vendor_path.read_text(encoding="utf-8").strip()
            product = product_path.read_text(encoding="utf-8").strip()
            return f"{vendor}:{product}"
    except OSError:
        return None

    return None


def detect_chipset(driver: Optional[str], usb_id: Optional[str]) -> Optional[str]:
    """Best-effort chipset detection from USB or driver metadata."""

    if usb_id and usb_id in USB_CHIPSET_MAP:
        return USB_CHIPSET_MAP[usb_id]

    if not driver:
        return None

    driver_name = driver.lower()
    for key, chipset in DRIVER_CHIPSET_MAP.items():
        if key.lower() in driver_name:
            return chipset

    return None


def populate_capabilities(adapter: WifiAdapter) -> None:
    """Populate supported modes and basic band metadata from `iw phy info`."""

    try:
        result = subprocess.run(
            ["iw", "phy", adapter.phy, "info"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return

    info = result.stdout.lower()
    if "monitor" in info:
        adapter.monitor_mode = True
        adapter.supported_modes.append("monitor")

    if "2412 mhz" in info or "2.4" in info:
        adapter.frequency_bands.append("2.4GHz")
    if "5180 mhz" in info or "5" in info:
        adapter.frequency_bands.append("5GHz")
    if "5955 mhz" in info or "6" in info:
        adapter.frequency_bands.append("6GHz")

    adapter.packet_injection = adapter.monitor_mode
