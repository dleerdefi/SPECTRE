#!/usr/bin/env python3
"""
Network Scanner Module

Core scanner functionality using airodump-ng with intelligent channel hopping.
Provides real-time network discovery and monitoring capabilities.
"""

import subprocess
import threading
import time
import logging
import tempfile
import signal
import os
from pathlib import Path
from typing import Optional, List, Dict, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from .models import Network, Client, ScanResult
from .parser import AirodumpParser

logger = logging.getLogger(__name__)


@dataclass
class ChannelStrategy:
    """Channel hopping configuration"""
    channels: List[int] = field(default_factory=lambda: [1, 6, 11])  # Default 2.4GHz
    dwell_time: float = 2.0  # Seconds per channel
    mode: str = "sequential"  # sequential, random, adaptive
    priority_channels: Dict[int, float] = field(default_factory=dict)  # Channel weights


class NetworkScanner:
    """Manages network scanning using airodump-ng"""

    def __init__(self, interface: str):
        """
        Initialize the scanner with a monitor-mode interface

        Args:
            interface: Monitor mode interface (e.g., 'wlan0mon')
        """
        self.interface = interface
        self.parser = AirodumpParser()
        self.process: Optional[subprocess.Popen] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.hop_thread: Optional[threading.Thread] = None
        self.is_scanning = False
        self.is_hopping = False

        # Scan results
        self.current_results = ScanResult()
        self.scan_start_time: Optional[datetime] = None

        # Channel management
        self.channel_strategy = ChannelStrategy()
        self.current_channel: Optional[int] = None

        # Callbacks
        self.on_network_found: Optional[Callable[[Network], None]] = None
        self.on_client_found: Optional[Callable[[Client], None]] = None
        self.on_handshake_captured: Optional[Callable[[Dict], None]] = None

        # File management
        self.output_dir = Path("/tmp/wifi-launchpad")
        self.output_dir.mkdir(exist_ok=True)
        self.current_csv_file: Optional[Path] = None

    def start_scan(
        self,
        channels: Optional[List[int]] = None,
        target_bssid: Optional[str] = None,
        write_interval: int = 5
    ) -> bool:
        """
        Start network scanning

        Args:
            channels: List of channels to scan (None for all)
            target_bssid: Specific BSSID to focus on
            write_interval: CSV write interval in seconds

        Returns:
            True if scan started successfully
        """
        if self.is_scanning:
            logger.warning("Scanner is already running")
            return False

        # Configure channels
        if channels:
            self.channel_strategy.channels = channels
        elif not self.channel_strategy.channels:
            # Default to common 2.4GHz and 5GHz channels
            self.channel_strategy.channels = [
                1, 6, 11,  # 2.4 GHz
                36, 40, 44, 48,  # 5 GHz lower
                149, 153, 157, 161  # 5 GHz upper
            ]

        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_csv_file = self.output_dir / f"scan_{timestamp}"

        # Build airodump-ng command
        cmd = self._build_airodump_command(
            target_bssid=target_bssid,
            write_interval=write_interval
        )

        try:
            # Start airodump-ng process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )

            self.is_scanning = True
            self.scan_start_time = datetime.now()

            # Start monitoring thread
            self.scan_thread = threading.Thread(
                target=self._monitor_scan,
                daemon=True
            )
            self.scan_thread.start()

            # Start channel hopping if not targeting specific BSSID
            if not target_bssid:
                self._start_channel_hopping()

            logger.info(f"Scanner started on interface {self.interface}")
            return True

        except Exception as e:
            logger.error(f"Failed to start scanner: {e}")
            self.is_scanning = False
            return False

    def stop_scan(self) -> ScanResult:
        """
        Stop the current scan

        Returns:
            Final scan results
        """
        if not self.is_scanning:
            logger.warning("Scanner is not running")
            return self.current_results

        self.is_scanning = False
        self.is_hopping = False

        # Stop channel hopping
        if self.hop_thread and self.hop_thread.is_alive():
            self.hop_thread.join(timeout=1)

        # Terminate airodump-ng process
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
            except:
                # Force kill if needed
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except:
                    pass
            self.process = None

        # Wait for monitoring thread
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)

        # Parse final results
        self._parse_results()

        # Calculate scan duration
        if self.scan_start_time:
            self.current_results.duration = (
                datetime.now() - self.scan_start_time
            ).total_seconds()

        logger.info(f"Scanner stopped. Found {len(self.current_results.networks)} networks")
        return self.current_results

    def set_channel(self, channel: int) -> bool:
        """
        Set the interface to a specific channel

        Args:
            channel: Channel number

        Returns:
            True if successful
        """
        try:
            subprocess.run(
                ["sudo", "iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True,
                capture_output=True
            )
            self.current_channel = channel
            logger.debug(f"Set channel to {channel}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set channel {channel}: {e}")
            return False

    def focus_on_target(self, bssid: str, channel: int) -> bool:
        """
        Focus scanning on a specific target

        Args:
            bssid: Target BSSID
            channel: Target channel

        Returns:
            True if refocused successfully
        """
        # Stop current scan
        if self.is_scanning:
            self.stop_scan()

        # Set channel
        if not self.set_channel(channel):
            return False

        # Start targeted scan
        return self.start_scan(channels=[channel], target_bssid=bssid)

    def set_channel_strategy(
        self,
        mode: str = "sequential",
        dwell_time: float = 2.0,
        priority_channels: Optional[Dict[int, float]] = None
    ):
        """
        Configure channel hopping strategy

        Args:
            mode: Hopping mode (sequential, random, adaptive)
            dwell_time: Time to spend on each channel
            priority_channels: Channel priorities for adaptive mode
        """
        self.channel_strategy.mode = mode
        self.channel_strategy.dwell_time = dwell_time
        if priority_channels:
            self.channel_strategy.priority_channels = priority_channels

    def _build_airodump_command(
        self,
        target_bssid: Optional[str] = None,
        write_interval: int = 5
    ) -> List[str]:
        """Build airodump-ng command with appropriate flags"""
        cmd = [
            "sudo", "airodump-ng",
            "-w", str(self.current_csv_file),  # Output prefix
            "--output-format", "csv",  # CSV format only
            "--write-interval", str(write_interval),  # Write interval
        ]

        # Add target BSSID if specified
        if target_bssid:
            cmd.extend(["--bssid", target_bssid])

        # Add interface
        cmd.append(self.interface)

        return cmd

    def _start_channel_hopping(self):
        """Start channel hopping thread"""
        if self.is_hopping:
            return

        self.is_hopping = True
        self.hop_thread = threading.Thread(
            target=self._channel_hop_worker,
            daemon=True
        )
        self.hop_thread.start()
        logger.debug("Channel hopping started")

    def _channel_hop_worker(self):
        """Worker thread for channel hopping"""
        import random

        while self.is_hopping and self.is_scanning:
            channels = self.channel_strategy.channels.copy()

            if self.channel_strategy.mode == "random":
                random.shuffle(channels)
            elif self.channel_strategy.mode == "adaptive":
                # Sort by priority
                channels = sorted(
                    channels,
                    key=lambda c: self.channel_strategy.priority_channels.get(c, 0),
                    reverse=True
                )

            for channel in channels:
                if not self.is_hopping:
                    break

                # Set channel
                self.set_channel(channel)

                # Calculate dwell time
                dwell_time = self.channel_strategy.dwell_time
                if self.channel_strategy.mode == "adaptive":
                    # Spend more time on priority channels
                    priority = self.channel_strategy.priority_channels.get(channel, 1.0)
                    dwell_time *= priority

                # Wait
                time.sleep(dwell_time)

    def _monitor_scan(self):
        """Monitor thread to parse results periodically"""
        while self.is_scanning:
            time.sleep(5)  # Parse every 5 seconds
            self._parse_results()

    def _parse_results(self):
        """Parse current CSV file and update results"""
        if not self.current_csv_file:
            return

        csv_file = Path(f"{self.current_csv_file}-01.csv")
        if not csv_file.exists():
            return

        try:
            # Parse CSV file
            new_results = self.parser.parse_csv_file(str(csv_file))

            # Update current results
            for network in new_results.networks:
                self.current_results.add_network(network)

                # Trigger callback for new networks
                if self.on_network_found:
                    self.on_network_found(network)

            for client in new_results.clients:
                self.current_results.add_client(client)

                # Trigger callback for new clients
                if self.on_client_found:
                    self.on_client_found(client)

            # Update channels scanned
            if self.current_channel and self.current_channel not in self.current_results.channels_scanned:
                self.current_results.channels_scanned.append(self.current_channel)

        except Exception as e:
            logger.error(f"Error parsing results: {e}")

    def get_current_results(self) -> ScanResult:
        """Get current scan results without stopping scan"""
        return self.current_results

    def update_channel_priorities(self, network_counts: Dict[int, int]):
        """
        Update channel priorities based on network density

        Args:
            network_counts: Dictionary of channel -> network count
        """
        total = sum(network_counts.values())
        if total == 0:
            return

        # Calculate priorities (more networks = higher priority)
        for channel, count in network_counts.items():
            self.channel_strategy.priority_channels[channel] = count / total

    def export_results(self, output_file: str, format: str = "json") -> bool:
        """
        Export scan results to file

        Args:
            output_file: Output file path
            format: Export format (json, csv)

        Returns:
            True if export successful
        """
        try:
            import json

            if format == "json":
                with open(output_file, 'w') as f:
                    json.dump(self.current_results.to_dict(), f, indent=2)
            else:
                logger.warning(f"Unsupported export format: {format}")
                return False

            logger.info(f"Results exported to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False