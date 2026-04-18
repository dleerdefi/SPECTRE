"""Packaged scanner service orchestration."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import asyncio
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.survey import Client, Network, ScanResult
from wifi_launchpad.providers.native.adapters import AdapterManager
from wifi_launchpad.providers.native.scanner import NetworkScanner
from wifi_launchpad.services.scanner_config import ScanConfig, ScanMode

logger = logging.getLogger(__name__)


class ScannerService:
    """Coordinate adapter setup, passive scans, and survey export."""

    def __init__(self) -> None:
        self.adapter_manager = AdapterManager()
        self.scanner: Optional[NetworkScanner] = None
        self.config: Optional[ScanConfig] = None
        self.is_running = False
        self.results = ScanResult()
        self.target_networks: List[Network] = []
        self.high_value_targets: List[Network] = []
        self.scan_stats = {
            "start_time": None,
            "total_networks": 0,
            "new_networks": 0,
            "total_clients": 0,
            "handshakes_captured": 0,
            "wps_vulnerable": 0,
        }
        self.on_target_found: Optional[Callable[[Network], None]] = None
        self.on_handshake_ready: Optional[Callable[[Network], None]] = None
        self.on_new_network: Optional[Callable[[Network], None]] = None

    async def initialize(self, provider: str = "auto") -> bool:
        """Discover adapters and initialize the scanner.

        Args:
            provider: "auto" (Kismet if available, else native), "kismet", or "native".
        """
        try:
            adapters = self.adapter_manager.discover_adapters()
            if not adapters:
                logger.error("No WiFi adapters found")
                return False

            monitor_adapter = self.adapter_manager.get_optimal_setup().get("monitor")
            if not monitor_adapter:
                monitor_adapter = next((adapter for adapter in adapters if adapter.monitor_mode), adapters[0])

            if not self.adapter_manager.enable_monitor_mode(monitor_adapter):
                logger.error("Failed to enable monitor mode on %s", monitor_adapter.interface)
                return False

            self._interface = monitor_adapter.interface
            self._provider = provider

            self.scanner = NetworkScanner(monitor_adapter.interface)
            self.scanner.on_network_found = self._handle_network_found
            self.scanner.on_client_found = self._handle_client_found
            logger.info("Scanner service initialized with %s (provider=%s)", monitor_adapter.interface, provider)
            return True
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to initialize scanner service: %s", exc)
            return False

    async def start_scan(self, config: ScanConfig) -> bool:
        """Start scanning with the requested mode."""

        if self.is_running:
            logger.warning("Scan already in progress")
            return False
        if not self.scanner and not await self.initialize():
            return False

        self.config = config
        self.is_running = True
        self.scan_stats["start_time"] = datetime.now()

        mode_handlers = {
            ScanMode.DISCOVERY: self._start_discovery_scan,
            ScanMode.TARGETED: self._start_targeted_scan,
            ScanMode.MONITOR: self._start_monitoring,
            ScanMode.RECON: self._start_recon_scan,
        }
        started = await mode_handlers[config.mode]()
        if not started:
            self.is_running = False
            return False

        if config.duration:
            asyncio.create_task(self._duration_timer(config.duration))
        return True

    async def stop_scan(self) -> ScanResult:
        """Stop an active scan and return the current results."""

        if not self.is_running:
            logger.warning("No scan in progress")
            return self.results

        self.is_running = False
        if self.scanner:
            self.results = self.scanner.stop_scan()

        self.scan_stats["total_networks"] = len(self.results.networks)
        self.scan_stats["total_clients"] = len(self.results.clients)
        logger.info("Scan stopped. Found %s networks", self.scan_stats["total_networks"])
        return self.results

    async def run_pipeline(self, duration: int = 90, on_phase: Optional[Callable] = None) -> ScanResult:
        """Run multi-tool survey pipeline (Kismet + wash + airodump + tshark).

        Falls back to native-only if provider is set to "native".
        """
        iface = getattr(self, "_interface", None)
        if not iface:
            logger.error("Scanner not initialized — call initialize() first")
            return ScanResult()
        provider = getattr(self, "_provider", "auto")
        if provider == "native":
            # Use existing single-tool path
            config = ScanConfig(mode=ScanMode.DISCOVERY, duration=duration)
            await self.start_scan(config)
            await asyncio.sleep(duration)
            return await self.stop_scan()
        from wifi_launchpad.services.survey_pipeline import SurveyPipeline
        pipeline = SurveyPipeline(interface=iface, on_phase=on_phase)
        return await pipeline.run(duration=duration)

    def get_statistics(self) -> Dict[str, Any]:
        """Return current scan statistics."""

        stats = self.scan_stats.copy()
        if stats["start_time"]:
            elapsed = (datetime.now() - stats["start_time"]).total_seconds()
            stats["elapsed_time"] = elapsed
            stats["networks_per_minute"] = stats["total_networks"] / (elapsed / 60) if elapsed > 0 else 0
        return stats

    def get_target_networks(self) -> List[Network]:
        """Return matching target networks discovered so far."""

        return self.target_networks

    def get_high_value_targets(self) -> List[Network]:
        """Return high-value targets sorted by priority."""

        return sorted(self.high_value_targets, key=lambda network: network.priority, reverse=True)

    def export_results(self, filepath: str) -> bool:
        """Persist the current scan results as JSON."""

        try:
            data = {
                "scan_info": {
                    "start_time": self.scan_stats["start_time"].isoformat() if self.scan_stats["start_time"] else None,
                    "mode": self.config.mode.value if self.config else None,
                    "statistics": self.get_statistics(),
                },
                "results": self.results.to_dict(),
                "targets": [network.to_dict() for network in self.target_networks],
                "high_value": [network.to_dict() for network in self.high_value_targets],
            }
            Path(filepath).write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info("Results exported to %s", filepath)
            return True
        except Exception as exc:
            logger.error("Failed to export results: %s", exc)
            return False

    async def quick_scan(self, duration: int = 30) -> ScanResult:
        """Run a short survey and stop automatically."""

        config = ScanConfig(mode=ScanMode.DISCOVERY, duration=duration, channel_dwell_time=1.5)
        await self.start_scan(config)
        await asyncio.sleep(duration)
        return await self.stop_scan()

    async def _start_discovery_scan(self) -> bool:
        logger.info("Starting discovery scan")
        channels = self.config.channels or list(get_settings().scan.default_channels)
        self.scanner.set_channel_strategy(mode="sequential", dwell_time=self.config.channel_dwell_time)
        success = self.scanner.start_scan(channels=channels, write_interval=self.config.write_interval)
        if not success:
            logger.error("Failed to start scanner")
        return success

    async def _start_targeted_scan(self) -> bool:
        if not self.config.target_bssid and not self.config.target_ssid:
            logger.error("No target specified for targeted scan")
            return False

        logger.info(
            "Starting targeted scan on %s",
            self.config.target_bssid or self.config.target_ssid,
        )
        target = None
        if self.config.target_bssid:
            target = next((network for network in self.results.networks if network.bssid == self.config.target_bssid), None)
        elif self.config.target_ssid:
            target = next((network for network in self.results.networks if network.ssid == self.config.target_ssid), None)

        if target:
            return self.scanner.focus_on_target(target.bssid, target.channel)
        return await self._start_discovery_scan()

    async def _start_monitoring(self) -> bool:
        logger.info("Starting continuous monitoring")
        self.scanner.set_channel_strategy(mode="sequential", dwell_time=self.config.channel_dwell_time)
        return self.scanner.start_scan(
            channels=self.config.channels,
            write_interval=self.config.write_interval,
        )

    async def _start_recon_scan(self) -> bool:
        logger.info("Starting reconnaissance scan")
        started = await self._start_discovery_scan()
        if self.config.enable_database:
            logger.warning("Database integration not yet implemented")
        return started

    async def _duration_timer(self, duration: int) -> None:
        await asyncio.sleep(duration)
        if self.is_running:
            logger.info("Scan duration (%ss) reached, stopping scan", duration)
            await self.stop_scan()

    def _handle_network_found(self, network: Network) -> None:
        if network not in self.results.networks:
            self.scan_stats["new_networks"] += 1

        if self.config:
            if self.config.target_bssid and network.bssid == self.config.target_bssid:
                network.is_target = True
                self.target_networks.append(network)
                if self.on_target_found:
                    self.on_target_found(network)
            elif self.config.target_ssid and network.ssid == self.config.target_ssid:
                network.is_target = True
                self.target_networks.append(network)
                if self.on_target_found:
                    self.on_target_found(network)

        if self._is_high_value(network):
            self.high_value_targets.append(network)
        if network.wps_enabled and not network.wps_locked:
            self.scan_stats["wps_vulnerable"] += 1
        if self.on_new_network:
            self.on_new_network(network)

    def _handle_client_found(self, client: Client) -> None:
        if not client.associated_bssid:
            return
        target = next((network for network in self.target_networks if network.bssid == client.associated_bssid), None)
        if target and self.on_handshake_ready:
            self.on_handshake_ready(target)

    def _is_high_value(self, network: Network) -> bool:
        return any(
            [
                network.wps_enabled and not network.wps_locked,
                network.encryption.value in ["WEP", "Open"],
                "corp" in network.ssid.lower(),
                "admin" in network.ssid.lower(),
                network.hidden,
                len(self.results.get_associated_clients(network.bssid)) > 5,
            ]
        )
