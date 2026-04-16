"""HCX capture and conversion wrapper (hcxdumptool v7+)."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Optional, Tuple

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import Handshake


class HCXCaptureProvider:
    """Capture WPA handshakes/PMKIDs with hcxdumptool v7 and convert with hcxtools.

    hcxdumptool v7+ changed CLI syntax:
      - `-w` (write) replaces `-o`
      - `--filtermode` removed; use `--bpf=<file>` (BPF) for filtering
      - `-A` enables active monitor mode (ACKs)
      - hcxdumptool manages its own monitor mode — pass raw interface
    """

    def __init__(self, interface: str, output_dir: Optional[Path] = None):
        self.interface = interface
        self.output_dir = Path(output_dir or get_settings().capture_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_available() -> bool:
        """Return whether the HCX capture pipeline is installed."""

        return bool(shutil.which("hcxdumptool") and shutil.which("hcxpcapngtool"))

    def capture_psk(
        self,
        *,
        target_channel: int,
        capture_timeout: int,
        target_bssid: Optional[str] = None,
        target_ssid: Optional[str] = None,
    ) -> Tuple[bool, Optional[Handshake], Optional[str]]:
        """Active capture: PMKID + 4-way handshake on a single interface."""

        return self._run_capture(
            target_channel=target_channel,
            capture_timeout=capture_timeout,
            target_bssid=target_bssid,
            target_ssid=target_ssid,
            prefix="hcx",
            require_pmkid=False,
        )

    def capture_pmkid(
        self,
        *,
        target_channel: int,
        capture_timeout: int = 30,
        target_bssid: Optional[str] = None,
        target_ssid: Optional[str] = None,
    ) -> Tuple[bool, Optional[Handshake], Optional[str]]:
        """PMKID-focused capture (shorter timeout, validates PMKID found)."""

        return self._run_capture(
            target_channel=target_channel,
            capture_timeout=capture_timeout,
            target_bssid=target_bssid,
            target_ssid=target_ssid,
            prefix="pmkid",
            require_pmkid=True,
        )

    def _run_capture(
        self,
        *,
        target_channel: int,
        capture_timeout: int,
        target_bssid: Optional[str],
        target_ssid: Optional[str],
        prefix: str,
        require_pmkid: bool,
    ) -> Tuple[bool, Optional[Handshake], Optional[str]]:
        """Internal: run hcxdumptool v7 with active mode and convert output."""

        if not self.is_available():
            return False, None, None

        started = datetime.now()
        stamp = started.strftime("%Y%m%d_%H%M%S")
        pcapng_path = self.output_dir / f"{prefix}_{stamp}_{self.interface}.pcapng"
        hash_path = self.output_dir / f"{prefix}_{stamp}_{self.interface}.22000"
        bpf_path: Optional[Path] = None

        # Build a BPF filter for the target BSSID to reduce noise
        if target_bssid:
            bpf_path = self.output_dir / f"{prefix}_{stamp}_filter.bpf"
            if not self._compile_bpf(target_bssid, bpf_path):
                bpf_path = None  # fall through to unfiltered capture

        cmd = [
            "sudo", "hcxdumptool",
            "-i", self.interface,
            "-w", str(pcapng_path),
            "-c", self._channel_spec(target_channel),
            "-A",  # active monitor mode (ACK frames) — required for PMKID/handshake solicitation
            "-t", "5",  # min stay time on channel
        ]
        if bpf_path:
            cmd.extend([f"--bpf={bpf_path}"])

        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            time.sleep(max(capture_timeout, 1))
        except Exception:
            self._stop_process(process)
            return False, None, None

        self._stop_process(process)

        if not pcapng_path.exists() or pcapng_path.stat().st_size == 0:
            return False, None, None

        if not self._convert_capture(pcapng_path, hash_path):
            return False, None, None

        if require_pmkid:
            has_pmkid = False
            try:
                content = hash_path.read_text(encoding="utf-8")
                has_pmkid = any(line.startswith("WPA*01*") for line in content.splitlines())
            except OSError:
                pass
            if not has_pmkid:
                return False, None, None

        if target_bssid and not self._hash_contains_target(hash_path, target_bssid):
            return False, None, None

        handshake = Handshake(
            bssid=target_bssid or "unknown",
            ssid=target_ssid or "Unknown",
            client_mac="unknown",
            pcap_file=str(pcapng_path),
            file_size=pcapng_path.stat().st_size,
            is_complete=True,
            quality_score=95.0 if require_pmkid else 100.0,
            capture_method="pmkid" if require_pmkid else "hcx",
            time_to_capture=max((datetime.now() - started).total_seconds(), 0.0),
        )
        return True, handshake, str(hash_path)

    def _compile_bpf(self, target_bssid: str, output_path: Path) -> bool:
        """Compile a BPF filter for the target BSSID and write to file."""
        try:
            # Match frames where wlan addr3 (BSSID) == target
            mac_no_colon = target_bssid.replace(":", "").lower()
            result = subprocess.run(
                ["hcxdumptool", "--bpfc=" f"wlan addr3 {mac_no_colon}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return False
            output_path.write_text(result.stdout, encoding="utf-8")
            return True
        except Exception:
            return False

    def _convert_capture(self, pcapng_path: Path, hash_path: Path) -> bool:
        """Convert a capture artifact into hashcat 22000 format."""

        try:
            subprocess.run(
                ["hcxpcapngtool", "-o", str(hash_path), str(pcapng_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.SubprocessError, OSError):
            return False
        return hash_path.exists() and hash_path.stat().st_size > 0

    def _hash_contains_target(self, hash_path: Path, target_bssid: str) -> bool:
        """Return whether the converted hash output appears to match the target AP."""

        normalized = target_bssid.replace(":", "").replace("-", "").lower()
        try:
            return any(normalized in line.lower() for line in hash_path.read_text(encoding="utf-8").splitlines())
        except OSError:
            return False

    def _channel_spec(self, channel: int) -> str:
        """Translate a WiFi channel into HCX's band-qualified channel syntax."""

        if channel <= 14:
            return f"{channel}a"
        if channel <= 196:
            return f"{channel}b"
        return str(channel)

    def _stop_process(self, process: Optional[subprocess.Popen]) -> None:
        """Terminate a running hcxdumptool process safely."""

        if not process:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception:
                pass
