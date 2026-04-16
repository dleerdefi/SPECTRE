"""Discovery helpers for the packaged quickstart preflight flow."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
from typing import Dict, List


ADAPTER_DB = {
    "0bda:8812": {
        "name": "ALFA AWUS036ACH",
        "chipset": "RTL8812AU",
        "driver": "realtek-rtl88xxau-dkms",
        "driver_check": "88XXau|8812au",
        "recommended_role": "monitoring",
    },
    "0e8d:7961": {
        "name": "ALFA AWUS036AXML",
        "chipset": "MT7921U",
        "driver": "mt7921u",
        "driver_check": "mt7921u",
        "recommended_role": "injection",
    },
    "148f:3070": {
        "name": "ALFA AWUS036NH",
        "chipset": "RT3070",
        "driver": "rt2800usb",
        "driver_check": "rt2800usb",
        "recommended_role": "legacy",
    },
    "0bda:8813": {
        "name": "ALFA AWUS1900",
        "chipset": "RTL8814AU",
        "driver": "realtek-rtl8814au-dkms",
        "driver_check": "8814au",
        "recommended_role": "high_power",
    },
}

WIFI_VENDOR_MARKERS = ("Realtek", "MediaTek", "Ralink", "Atheros")


def detect_usb_adapters() -> List[Dict[str, str]]:
    """Return USB WiFi devices that look relevant to quickstart workflows."""

    adapters: List[Dict[str, str]] = []
    try:
        result = subprocess.run(["lsusb"], capture_output=True, text=True, check=False)
    except OSError:
        return adapters

    for line in result.stdout.splitlines():
        if not any(vendor in line for vendor in WIFI_VENDOR_MARKERS):
            continue
        match = re.search(r"ID ([0-9a-f]{4}:[0-9a-f]{4})", line, re.IGNORECASE)
        if match:
            adapters.append({"id": match.group(1).lower(), "description": line})
    return adapters


def detect_interfaces() -> List[Dict[str, str]]:
    """Return wireless interfaces discovered via `iw dev`."""

    interfaces: List[Dict[str, str]] = []
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
    except OSError:
        return interfaces

    current: Dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "Interface" in line:
            if current:
                interfaces.append(current)
            current = {"name": line.split("Interface", 1)[1].strip()}
        elif "addr" in line and current:
            current["mac"] = line.split("addr", 1)[1].strip()
        elif "type" in line and current:
            current["type"] = line.split("type", 1)[1].strip()

    if current:
        interfaces.append(current)

    for interface in interfaces:
        driver_path = Path(f"/sys/class/net/{interface['name']}/device/driver")
        if driver_path.exists():
            interface["driver"] = driver_path.resolve().name

    return interfaces


def supports_monitor_mode() -> bool:
    """Return whether the platform reports monitor-mode capability."""

    try:
        result = subprocess.run(["iw", "list"], capture_output=True, text=True, check=False)
    except OSError:
        return False
    return "monitor" in result.stdout.lower()

