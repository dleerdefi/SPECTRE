"""Airodump-ng scanner orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import random
import signal
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.survey import Client, Network, ScanResult

from .airodump_parser import AirodumpParser

logger = logging.getLogger(__name__)


@dataclass
class ChannelStrategy:
    """Channel hopping configuration."""

    channels: List[int] = field(default_factory=lambda: [1, 6, 11])
    dwell_time: float = 2.0
    mode: str = "sequential"
    priority_channels: Dict[int, float] = field(default_factory=dict)


class NetworkScanner:
    """Manage passive scans via airodump-ng with optional channel hopping."""

    def __init__(self, interface: str):
        self.interface = interface
        self.parser = AirodumpParser()
        self.process: Optional[subprocess.Popen] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.hop_thread: Optional[threading.Thread] = None
        self.is_scanning = False
        self.is_hopping = False
        self.current_results = ScanResult()
        self.scan_start_time: Optional[datetime] = None
        self.channel_strategy = ChannelStrategy()
        self.current_channel: Optional[int] = None
        self.on_network_found: Optional[Callable[[Network], None]] = None
        self.on_client_found: Optional[Callable[[Client], None]] = None
        self.on_handshake_captured: Optional[Callable[[Dict], None]] = None
        self.output_dir = get_settings().temp_dir
        self.output_dir.mkdir(exist_ok=True)
        self.current_csv_file: Optional[Path] = None

    def start_scan(self, channels: Optional[List[int]] = None, target_bssid: Optional[str] = None, write_interval: int = 5) -> bool:
        """Start a passive scan."""

        if self.is_scanning:
            logger.warning("Scanner is already running")
            return False
        if channels:
            self.channel_strategy.channels = channels
        elif not self.channel_strategy.channels:
            self.channel_strategy.channels = list(get_settings().scan.default_channels)
        if self.channel_strategy.channels:
            self.current_channel = self.channel_strategy.channels[0]

        self.current_results = ScanResult()
        self.current_results.channels_scanned = list(self.channel_strategy.channels)
        self.current_csv_file = self.output_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cmd = [
            "sudo",
            "airodump-ng",
            "-w",
            str(self.current_csv_file),
            "--output-format",
            "csv",
            "--write-interval",
            str(write_interval),
        ]
        if target_bssid:
            cmd.extend(["--bssid", target_bssid])
        channel_argument = self._build_channel_argument(target_bssid)
        if channel_argument:
            # Pre-tune to the first requested channel to reduce startup bleed from
            # whatever channel the interface was previously monitoring.
            self.set_channel(self.channel_strategy.channels[0])
            cmd.extend(["--channel", channel_argument])
        cmd.append(self.interface)

        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        except Exception as exc:
            logger.error("Failed to start scanner: %s", exc)
            self.is_scanning = False
            return False

        self.is_scanning = True
        self.scan_start_time = datetime.now()
        self.scan_thread = threading.Thread(target=self._monitor_scan, daemon=True)
        self.scan_thread.start()
        if not target_bssid and self.channel_strategy.mode != "sequential":
            self._start_channel_hopping()
        logger.info("Scanner started on interface %s", self.interface)
        return True

    def stop_scan(self) -> ScanResult:
        """Stop the current scan and return final results."""

        if not self.is_scanning:
            logger.warning("Scanner is not running")
            return self.current_results

        self.is_scanning = False
        self.is_hopping = False
        if self.hop_thread and self.hop_thread.is_alive():
            self.hop_thread.join(timeout=1)
        if self.process:
            self._stop_process(self.process)
            self.process = None
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)

        self._parse_results()
        if self.scan_start_time:
            self.current_results.duration = (datetime.now() - self.scan_start_time).total_seconds()
        logger.info("Scanner stopped. Found %s networks", len(self.current_results.networks))
        return self.current_results

    def set_channel(self, channel: int) -> bool:
        """Set the interface channel."""

        try:
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "channel", str(channel)], check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to set channel %s: %s", channel, exc)
            return False
        self.current_channel = channel
        logger.debug("Set channel to %s", channel)
        return True

    def focus_on_target(self, bssid: str, channel: int) -> bool:
        """Refocus the scanner on a target BSSID/channel pair."""

        if self.is_scanning:
            self.stop_scan()
        if not self.set_channel(channel):
            return False
        return self.start_scan(channels=[channel], target_bssid=bssid)

    def set_channel_strategy(self, mode: str = "sequential", dwell_time: float = 2.0, priority_channels: Optional[Dict[int, float]] = None) -> None:
        """Configure channel hopping behavior."""

        self.channel_strategy.mode = mode
        self.channel_strategy.dwell_time = dwell_time
        if priority_channels:
            self.channel_strategy.priority_channels = priority_channels

    def get_current_results(self) -> ScanResult:
        """Return current results without stopping the scan."""

        return self.current_results

    def update_channel_priorities(self, network_counts: Dict[int, int]) -> None:
        """Update adaptive priorities based on observed channel density."""

        total = sum(network_counts.values())
        if total == 0:
            return
        self.channel_strategy.priority_channels = {
            channel: count / total for channel, count in network_counts.items()
        }

    def export_results(self, output_file: str, format: str = "json") -> bool:
        """Export current scan results."""

        if format != "json":
            logger.warning("Unsupported export format: %s", format)
            return False
        try:
            Path(output_file).write_text(json.dumps(self.current_results.to_dict(), indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to export results: %s", exc)
            return False
        logger.info("Results exported to %s", output_file)
        return True

    def _start_channel_hopping(self) -> None:
        if self.is_hopping:
            return
        self.is_hopping = True
        self.hop_thread = threading.Thread(target=self._channel_hop_worker, daemon=True)
        self.hop_thread.start()
        logger.debug("Channel hopping started")

    def _channel_hop_worker(self) -> None:
        while self.is_hopping and self.is_scanning:
            channels = self._ordered_channels()
            for channel in channels:
                if not self.is_hopping:
                    return
                self.set_channel(channel)
                time.sleep(self._dwell_time(channel))

    def _ordered_channels(self) -> List[int]:
        channels = self.channel_strategy.channels.copy()
        if self.channel_strategy.mode == "random":
            random.shuffle(channels)
        elif self.channel_strategy.mode == "adaptive":
            channels = sorted(channels, key=lambda channel: self.channel_strategy.priority_channels.get(channel, 0), reverse=True)
        return channels

    def _dwell_time(self, channel: int) -> float:
        dwell_time = self.channel_strategy.dwell_time
        if self.channel_strategy.mode == "adaptive":
            dwell_time *= self.channel_strategy.priority_channels.get(channel, 1.0)
        return dwell_time

    def _monitor_scan(self) -> None:
        time.sleep(2)
        while self.is_scanning:
            self._parse_results()
            time.sleep(3)

    def _build_channel_argument(self, target_bssid: Optional[str]) -> Optional[str]:
        """Return an airodump-ng channel argument when the scan plan is explicit."""

        if target_bssid and self.channel_strategy.channels:
            return ",".join(str(channel) for channel in self.channel_strategy.channels)
        if self.channel_strategy.mode == "sequential" and self.channel_strategy.channels:
            return ",".join(str(channel) for channel in self.channel_strategy.channels)
        return None

    def _parse_results(self) -> None:
        if not self.current_csv_file:
            return
        csv_file = Path(f"{self.current_csv_file}-01.csv")
        if not csv_file.exists() or csv_file.stat().st_size == 0:
            return
        try:
            new_results = self.parser.parse_csv_file(str(csv_file))
        except Exception as exc:
            logger.error("Error parsing results: %s", exc)
            return

        for network in new_results.networks:
            self.current_results.add_network(network)
            if self.on_network_found:
                self.on_network_found(network)
        for client in new_results.clients:
            self.current_results.add_client(client)
            if self.on_client_found:
                self.on_client_found(client)
        if self.current_channel and self.current_channel not in self.current_results.channels_scanned:
            self.current_results.channels_scanned.append(self.current_channel)
        observed_channels = sorted(
            {
                network.channel
                for network in self.current_results.networks
                if network.channel > 0 and network.channel not in self.current_results.channels_scanned
            }
        )
        self.current_results.channels_scanned.extend(observed_channels)

    def _stop_process(self, process: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception:
                pass
