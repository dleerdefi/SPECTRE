#!/usr/bin/env python3
"""
Scanner Service Orchestrator

High-level service that coordinates scanning operations, adapter management,
and data persistence. Provides a simple interface for complex scanning workflows.
"""

import asyncio
import logging
import json
from typing import Optional, List, Dict, Callable, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from core.scanner import NetworkScanner, Network, Client, ScanResult, ChannelStrategy
from core.adapters import AdapterManager

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    """Scanning modes"""
    DISCOVERY = "discovery"  # Broad network discovery
    TARGETED = "targeted"  # Focus on specific network
    MONITOR = "monitor"  # Continuous monitoring
    RECON = "recon"  # Reconnaissance with database updates


@dataclass
class ScanConfig:
    """Scan configuration"""
    mode: ScanMode = ScanMode.DISCOVERY
    channels: Optional[List[int]] = None
    target_bssid: Optional[str] = None
    target_ssid: Optional[str] = None
    duration: Optional[int] = None  # Seconds (None for continuous)
    channel_dwell_time: float = 2.0
    write_interval: int = 5
    enable_database: bool = False
    enable_alerts: bool = True


class ScannerService:
    """Orchestrates scanning operations"""

    def __init__(self):
        self.adapter_manager = AdapterManager()
        self.scanner: Optional[NetworkScanner] = None
        self.config: Optional[ScanConfig] = None
        self.is_running = False

        # Results
        self.results = ScanResult()
        self.target_networks: List[Network] = []
        self.high_value_targets: List[Network] = []

        # Statistics
        self.scan_stats = {
            "start_time": None,
            "total_networks": 0,
            "new_networks": 0,
            "total_clients": 0,
            "handshakes_captured": 0,
            "wps_vulnerable": 0
        }

        # Callbacks
        self.on_target_found: Optional[Callable[[Network], None]] = None
        self.on_handshake_ready: Optional[Callable[[Network], None]] = None
        self.on_new_network: Optional[Callable[[Network], None]] = None

    async def initialize(self) -> bool:
        """
        Initialize the scanner service

        Returns:
            True if initialization successful
        """
        try:
            # Discover adapters
            adapters = self.adapter_manager.discover_adapters()
            if not adapters:
                logger.error("No WiFi adapters found")
                return False

            # Get optimal adapter for monitoring
            optimal = self.adapter_manager.get_optimal_setup()
            monitor_adapter = optimal.get("monitor")

            if not monitor_adapter:
                # Use first capable adapter
                monitor_adapter = next(
                    (a for a in adapters if a.monitor_mode),
                    adapters[0]
                )

            # Enable monitor mode
            if not self.adapter_manager.enable_monitor_mode(monitor_adapter):
                logger.error(f"Failed to enable monitor mode on {monitor_adapter.interface}")
                return False

            # Create scanner instance
            self.scanner = NetworkScanner(monitor_adapter.interface)

            # Set up callbacks
            self.scanner.on_network_found = self._handle_network_found
            self.scanner.on_client_found = self._handle_client_found

            logger.info(f"Scanner service initialized with {monitor_adapter.interface}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize scanner service: {e}")
            return False

    async def start_scan(self, config: ScanConfig) -> bool:
        """
        Start scanning with specified configuration

        Args:
            config: Scan configuration

        Returns:
            True if scan started successfully
        """
        if self.is_running:
            logger.warning("Scan already in progress")
            return False

        if not self.scanner:
            if not await self.initialize():
                return False

        self.config = config
        self.is_running = True
        self.scan_stats["start_time"] = datetime.now()

        # Configure scanner based on mode
        if config.mode == ScanMode.DISCOVERY:
            await self._start_discovery_scan()
        elif config.mode == ScanMode.TARGETED:
            await self._start_targeted_scan()
        elif config.mode == ScanMode.MONITOR:
            await self._start_monitoring()
        elif config.mode == ScanMode.RECON:
            await self._start_recon_scan()

        # Start duration timer if specified
        if config.duration:
            asyncio.create_task(self._duration_timer(config.duration))

        return True

    async def stop_scan(self) -> ScanResult:
        """
        Stop current scan

        Returns:
            Final scan results
        """
        if not self.is_running:
            logger.warning("No scan in progress")
            return self.results

        self.is_running = False

        if self.scanner:
            self.results = self.scanner.stop_scan()

        # Update statistics
        self.scan_stats["total_networks"] = len(self.results.networks)
        self.scan_stats["total_clients"] = len(self.results.clients)

        logger.info(f"Scan stopped. Found {self.scan_stats['total_networks']} networks")
        return self.results

    async def _start_discovery_scan(self):
        """Start broad discovery scan"""
        logger.info("Starting discovery scan")

        # Use all common channels
        channels = self.config.channels or [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,  # 2.4 GHz
            36, 40, 44, 48,  # 5 GHz lower
            149, 153, 157, 161, 165  # 5 GHz upper
        ]

        # Configure adaptive channel hopping
        self.scanner.set_channel_strategy(
            mode="adaptive",
            dwell_time=self.config.channel_dwell_time
        )

        # Start scan
        self.scanner.start_scan(
            channels=channels,
            write_interval=self.config.write_interval
        )

    async def _start_targeted_scan(self):
        """Start targeted scan on specific network"""
        if not self.config.target_bssid and not self.config.target_ssid:
            logger.error("No target specified for targeted scan")
            return

        logger.info(f"Starting targeted scan on {self.config.target_bssid or self.config.target_ssid}")

        # Find target in existing results
        target = None
        if self.config.target_bssid:
            target = next(
                (n for n in self.results.networks if n.bssid == self.config.target_bssid),
                None
            )
        elif self.config.target_ssid:
            target = next(
                (n for n in self.results.networks if n.ssid == self.config.target_ssid),
                None
            )

        if target:
            # Focus on target channel
            self.scanner.focus_on_target(target.bssid, target.channel)
        else:
            # Start discovery to find target
            await self._start_discovery_scan()

    async def _start_monitoring(self):
        """Start continuous monitoring mode"""
        logger.info("Starting continuous monitoring")

        # Use sequential channel hopping for monitoring
        self.scanner.set_channel_strategy(
            mode="sequential",
            dwell_time=self.config.channel_dwell_time
        )

        # Start scan
        self.scanner.start_scan(
            channels=self.config.channels,
            write_interval=self.config.write_interval
        )

    async def _start_recon_scan(self):
        """Start reconnaissance scan with database updates"""
        logger.info("Starting reconnaissance scan")

        # Similar to discovery but with database integration
        await self._start_discovery_scan()

        # TODO: Enable database updates when database module is implemented
        if self.config.enable_database:
            logger.warning("Database integration not yet implemented")

    async def _duration_timer(self, duration: int):
        """Auto-stop scan after specified duration"""
        await asyncio.sleep(duration)
        if self.is_running:
            logger.info(f"Scan duration ({duration}s) reached, stopping scan")
            await self.stop_scan()

    def _handle_network_found(self, network: Network):
        """Handle new network discovery"""
        # Update statistics
        if network not in self.results.networks:
            self.scan_stats["new_networks"] += 1

        # Check if target
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

        # Check for high-value characteristics
        if self._is_high_value(network):
            self.high_value_targets.append(network)

        # Check for WPS
        if network.wps_enabled and not network.wps_locked:
            self.scan_stats["wps_vulnerable"] += 1

        # Trigger callback
        if self.on_new_network:
            self.on_new_network(network)

    def _handle_client_found(self, client: Client):
        """Handle new client discovery"""
        # Check if client is associated with target
        if client.associated_bssid:
            target = next(
                (n for n in self.target_networks if n.bssid == client.associated_bssid),
                None
            )
            if target and self.on_handshake_ready:
                # Target has associated client - ready for handshake capture
                self.on_handshake_ready(target)

    def _is_high_value(self, network: Network) -> bool:
        """Determine if network is high-value target"""
        # High value indicators
        high_value_indicators = [
            network.wps_enabled and not network.wps_locked,  # WPS vulnerable
            network.encryption.value in ["WEP", "Open"],  # Weak encryption
            "corp" in network.ssid.lower(),  # Corporate network
            "admin" in network.ssid.lower(),  # Admin network
            network.hidden,  # Hidden network
            len(self.results.get_associated_clients(network.bssid)) > 5  # Many clients
        ]
        return any(high_value_indicators)

    def get_statistics(self) -> Dict[str, Any]:
        """Get current scan statistics"""
        stats = self.scan_stats.copy()
        if stats["start_time"]:
            elapsed = (datetime.now() - stats["start_time"]).total_seconds()
            stats["elapsed_time"] = elapsed
            stats["networks_per_minute"] = (
                stats["total_networks"] / (elapsed / 60) if elapsed > 0 else 0
            )
        return stats

    def get_target_networks(self) -> List[Network]:
        """Get discovered target networks"""
        return self.target_networks

    def get_high_value_targets(self) -> List[Network]:
        """Get high-value targets sorted by priority"""
        return sorted(self.high_value_targets, key=lambda n: n.priority, reverse=True)

    def export_results(self, filepath: str) -> bool:
        """
        Export scan results to file

        Args:
            filepath: Output file path

        Returns:
            True if export successful
        """
        try:
            data = {
                "scan_info": {
                    "start_time": self.scan_stats["start_time"].isoformat() if self.scan_stats["start_time"] else None,
                    "mode": self.config.mode.value if self.config else None,
                    "statistics": self.get_statistics()
                },
                "results": self.results.to_dict(),
                "targets": [n.to_dict() for n in self.target_networks],
                "high_value": [n.to_dict() for n in self.high_value_targets]
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Results exported to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False

    async def quick_scan(self, duration: int = 30) -> ScanResult:
        """
        Perform a quick scan for specified duration

        Args:
            duration: Scan duration in seconds

        Returns:
            Scan results
        """
        config = ScanConfig(
            mode=ScanMode.DISCOVERY,
            duration=duration,
            channel_dwell_time=1.5  # Faster hopping for quick scan
        )

        await self.start_scan(config)
        await asyncio.sleep(duration)
        return await self.stop_scan()