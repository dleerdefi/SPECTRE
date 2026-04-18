"""WPS detection via wash (part of Reaver suite).

Runs ``wash -i <iface> -s`` in single-pass mode to detect WPS-enabled APs,
their WPS version, and lock status. Results merge into the survey ScanResult.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class WpsInfo:
    """WPS status for a single AP."""

    bssid: str
    channel: int
    wps_version: str
    wps_locked: bool
    ssid: str = ""


def is_available() -> bool:
    """Check if wash is installed."""
    return shutil.which("wash") is not None


async def scan_wps(interface: str, timeout: int = 15) -> List[WpsInfo]:
    """Run wash and return WPS-enabled APs.

    Args:
        interface: Monitor-mode interface (e.g., wlan0mon).
        timeout: Seconds to scan before stopping.

    Returns:
        List of WpsInfo for each WPS-enabled AP detected.
    """
    if not is_available():
        logger.info("wash not installed — skipping WPS scan")
        return []

    cmd = ["sudo", "wash", "-i", interface, "-s"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.terminate()
            stdout, _ = await proc.communicate()

        return _parse_wash_output(stdout.decode("utf-8", errors="replace"))

    except Exception as exc:
        logger.debug("wash scan failed: %s", exc)
        return []


def _parse_wash_output(output: str) -> List[WpsInfo]:
    """Parse wash stdout into WpsInfo objects.

    Wash output format (tab-separated):
    BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
    AA:BB:CC:DD:EE:FF   6   -45  2.0  No   RalinkTe  MyNetwork
    """
    results: list[WpsInfo] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            bssid = parts[0]
            channel = int(parts[1])
            wps_version = parts[3]
            wps_locked = parts[4].lower() == "yes"
            ssid = " ".join(parts[6:]) if len(parts) > 6 else ""
            results.append(WpsInfo(
                bssid=bssid, channel=channel,
                wps_version=wps_version, wps_locked=wps_locked, ssid=ssid,
            ))
        except (ValueError, IndexError):
            continue
    return results


def merge_wps_into_networks(networks, wps_results: List[WpsInfo]) -> int:
    """Update Network objects with WPS data from wash. Returns count merged."""
    wps_map: Dict[str, WpsInfo] = {w.bssid.upper(): w for w in wps_results}
    merged = 0
    for net in networks:
        info = wps_map.get(net.bssid.upper())
        if info:
            net.wps_enabled = True
            net.wps_locked = info.wps_locked
            merged += 1
    return merged


__all__ = ["WpsInfo", "is_available", "merge_wps_into_networks", "scan_wps"]
