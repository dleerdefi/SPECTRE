"""Adapter management orchestrator."""

from __future__ import annotations

import logging
import subprocess
from typing import Dict, List, Optional

from .discovery import get_wireless_interfaces, load_adapter, populate_capabilities
from .models import WifiAdapter

logger = logging.getLogger(__name__)


class AdapterManager:
    """Manage WiFi adapters for survey and capture workflows."""

    OPTIMAL_CONFIGS = {
        # RTL8812AU handles all operations: scan, capture, injection, deauth.
        # Assigned both monitor and injection roles (single-adapter workflow).
        "RTL8812AU": {"role": "all", "tx_power": 30, "preferred_channels": [1, 6, 11, 36, 40, 44, 48]},
        "RT3070": {"role": "legacy", "tx_power": 30, "bands": ["2.4GHz"]},
    }

    # Chipsets that report monitor/injection capability but are broken in practice.
    # These are forced to management-only role.
    # MT7921U: broken injection (mt76 driver), degraded passive monitor
    # (can't see associated clients), crashes Kismet.
    # See: morrownr/USB-WiFi#387, openwrt/mt76#839
    # Chipsets forced to management-only:
    # MT7921U: broken injection, degraded monitor, crashes Kismet
    # QCA9xxx: built-in adapter, keep for internet connectivity
    BLOCKED_CHIPSETS = {"MT7921U", "QCA9xxx"}

    def __init__(self) -> None:
        self.adapters: List[WifiAdapter] = []
        self.monitor_adapter: Optional[WifiAdapter] = None
        self.injection_adapter: Optional[WifiAdapter] = None
        self.management_adapter: Optional[WifiAdapter] = None

    def discover_adapters(self) -> List[WifiAdapter]:
        """Discover and score all wireless adapters on the system."""

        self.adapters = []
        for interface in get_wireless_interfaces():
            adapter = load_adapter(interface)
            if not adapter:
                continue
            populate_capabilities(adapter)
            self.adapters.append(adapter)

        self._assign_roles()
        logger.info("Discovered %s WiFi adapters", len(self.adapters))
        return self.adapters

    def _assign_roles(self) -> None:
        self.monitor_adapter = None
        self.injection_adapter = None
        self.management_adapter = None

        for adapter in self.adapters:
            adapter.assigned_role = None

        sorted_adapters = sorted(self.adapters, key=self._score_adapter, reverse=True)
        for adapter in sorted_adapters:
            config = self.OPTIMAL_CONFIGS.get(adapter.chipset)
            if not config:
                continue
            role = config["role"]
            if role == "all":
                adapter.assigned_role = "injection"
                self.injection_adapter = adapter
                if not self.monitor_adapter:
                    self.monitor_adapter = adapter
            elif role == "monitor" and not self.monitor_adapter:
                adapter.assigned_role = "monitor"
                self.monitor_adapter = adapter
            elif role == "injection" and not self.injection_adapter:
                adapter.assigned_role = "injection"
                self.injection_adapter = adapter

        for adapter in sorted_adapters:
            if adapter.assigned_role:
                continue
            if adapter.chipset in self.BLOCKED_CHIPSETS:
                adapter.assigned_role = "management"
                if not self.management_adapter:
                    self.management_adapter = adapter
                continue
            if not self.monitor_adapter and adapter.monitor_mode:
                adapter.assigned_role = "monitor"
                self.monitor_adapter = adapter
            elif not self.injection_adapter and adapter.packet_injection:
                adapter.assigned_role = "injection"
                self.injection_adapter = adapter
            elif not self.management_adapter:
                adapter.assigned_role = "management"
                self.management_adapter = adapter

    def _score_adapter(self, adapter: WifiAdapter) -> int:
        score = 0
        if adapter.monitor_mode:
            score += 10
        if adapter.packet_injection:
            score += 10
        if "5GHz" in adapter.frequency_bands:
            score += 5
        if adapter.chipset in self.OPTIMAL_CONFIGS:
            score += 20
        return score

    def enable_monitor_mode(self, adapter: WifiAdapter) -> bool:
        """Switch an adapter into monitor mode (always verifies live state)."""

        live_mode = self._get_live_mode(adapter.interface)
        if live_mode == "monitor":
            adapter.current_mode = "monitor"
            logger.info("%s already in monitor mode", adapter.interface)
            return True
        if not self._reset_interface_mode(adapter.interface, "monitor"):
            return False
        # Verify it actually took effect
        if self._get_live_mode(adapter.interface) != "monitor":
            logger.error("%s failed to enter monitor mode", adapter.interface)
            return False
        adapter.current_mode = "monitor"
        logger.info("Enabled monitor mode on %s", adapter.interface)
        return True

    def disable_monitor_mode(self, adapter: WifiAdapter) -> bool:
        """Return an adapter to managed mode."""

        live_mode = self._get_live_mode(adapter.interface)
        if live_mode == "managed":
            adapter.current_mode = "managed"
            return True
        if not self._reset_interface_mode(adapter.interface, "managed"):
            return False
        adapter.current_mode = "managed"
        logger.info("Disabled monitor mode on %s", adapter.interface)
        return True

    def _get_live_mode(self, interface: str) -> str:
        """Query the actual current mode from `iw dev info`."""
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True, timeout=3,
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("type "):
                    return line.split()[1]
        except Exception:
            pass
        return "unknown"

    def _reset_interface_mode(self, interface: str, mode: str) -> bool:
        try:
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "iw", "dev", interface, "set", "type", mode], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to set %s to %s mode: %s", interface, mode, exc)
            return False

    def set_channel(self, adapter: WifiAdapter, channel: int) -> bool:
        """Pin an adapter to a specific channel."""

        try:
            subprocess.run(
                ["sudo", "iw", "dev", adapter.interface, "set", "channel", str(channel)],
                check=True,
            )
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to set channel on %s: %s", adapter.interface, exc)
            return False

        adapter.current_channel = channel
        logger.info("Set %s to channel %s", adapter.interface, channel)
        return True

    def test_injection(self, adapter: WifiAdapter) -> bool:
        """Run a basic aireplay injection test."""

        if adapter.current_mode != "monitor" and not self.enable_monitor_mode(adapter):
            return False

        try:
            result = subprocess.run(
                ["sudo", "aireplay-ng", "--test", adapter.interface],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            logger.error("Injection test error on %s: %s", adapter.interface, exc)
            return False

        if "Injection is working!" in result.stdout:
            logger.info("Injection test passed on %s", adapter.interface)
            return True

        logger.warning("Injection test failed on %s", adapter.interface)
        return False

    def get_optimal_setup(self) -> Dict[str, Optional[WifiAdapter]]:
        """Return the assigned adapter roles."""

        return {
            "monitor": self.monitor_adapter,
            "injection": self.injection_adapter,
            "management": self.management_adapter,
        }

    def summary(self) -> str:
        """Return a compact text summary of detected adapters."""

        lines = [f"Found {len(self.adapters)} WiFi adapter(s):"]
        for adapter in self.adapters:
            lines.append(
                f"  - {adapter.interface}: {adapter.chipset or 'Unknown'} "
                f"({adapter.assigned_role or 'No role'})"
            )
            lines.append(f"    Mode: {adapter.current_mode}")
            lines.append(f"    Bands: {', '.join(adapter.frequency_bands)}")
            if adapter.current_channel:
                lines.append(f"    Channel: {adapter.current_channel}")

        if self.monitor_adapter and self.injection_adapter:
            lines.append("")
            lines.append("Dual-adapter configuration ready")
            lines.append(f"  Monitor: {self.monitor_adapter.interface}")
            lines.append(f"  Injection: {self.injection_adapter.interface}")

        return "\n".join(lines)

