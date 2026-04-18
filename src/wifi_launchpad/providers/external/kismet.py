"""Kismet-backed passive survey provider — reads directly from Kismet's SQLite DB."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Iterable, List, Optional, Tuple

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.evidence import EvidenceArtifact
from wifi_launchpad.domain.survey import ScanResult
from wifi_launchpad.providers.external.kismet_client import KismetDbReader, KismetRestClient, find_kismet_db
from wifi_launchpad.providers.external.kismet_mapper import map_devices_to_scan_result
from wifi_launchpad.providers.native.adapters import AdapterManager


class KismetSurveyProvider:
    """Run a bounded passive survey with Kismet and read results from its SQLite DB."""

    def __init__(
        self,
        interface: Optional[str] = None,
        output_dir: Optional[Path] = None,
        run_root: Optional[Path] = None,
        adapter_manager: Optional[AdapterManager] = None,
    ) -> None:
        settings = get_settings()
        self.interface = interface
        self.output_dir = Path(output_dir or settings.capture_dir / "surveys")
        self.run_root = Path(run_root or settings.temp_dir / "kismet")
        self.adapter_manager = adapter_manager or AdapterManager()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.run_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_available() -> bool:
        """Return whether Kismet is installed."""
        return bool(shutil.which("kismet"))

    def run_survey(
        self,
        *,
        duration: int,
        channels: Optional[Iterable[int]] = None,
    ) -> Tuple[ScanResult, List[EvidenceArtifact]]:
        """Collect a passive survey with Kismet and extract data from its database."""

        if not self.is_available():
            raise RuntimeError("Kismet survey requires kismet to be installed")

        started_at = datetime.now()
        interfaces = self._select_interfaces()
        stamp = started_at.strftime("kismet_%Y%m%d_%H%M%S")
        run_dir = self.run_root / stamp
        log_dir = self.output_dir / stamp
        run_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)

        log_path = run_dir / "kismet.log"

        # Pre-create httpd config so Kismet doesn't prompt on first run
        kismet_home = run_dir / ".kismet"
        kismet_home.mkdir(parents=True, exist_ok=True)
        httpd_conf = kismet_home / "kismet_httpd.conf"
        httpd_conf.write_text(
            "httpd_username=spectre\nhttpd_password=spectre\n",
            encoding="utf-8",
        )

        cmd = [
            "sudo", "kismet",
            "--silent", "--no-ncurses", "--no-plugins",
            "--homedir", str(run_dir),
            "-t", stamp,
            "-p", str(log_dir),
        ]
        for iface in interfaces:
            cmd.extend(["-c", iface])

        process = None
        log_handle = log_path.open("w", encoding="utf-8")
        try:
            process = subprocess.Popen(
                cmd,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
            )
            self._wait_for_capture_window(process, duration)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"Failed to start Kismet survey: {exc}") from exc
        finally:
            self._stop_process(process)
            log_handle.close()

        db_path = find_kismet_db(log_dir)
        if not db_path:
            raise RuntimeError("Kismet did not produce a .kismet database")

        reader = KismetDbReader(db_path)
        devices = reader.read_devices()
        scan_result = map_devices_to_scan_result(devices, channels=channels)
        scan_result.scan_time = started_at
        scan_result.duration = float(duration)
        if channels:
            scan_result.channels_scanned = sorted({int(ch) for ch in channels})

        artifacts = [
            EvidenceArtifact(
                artifact_id=f"{stamp}-kismetdb",
                kind="kismet_db",
                source_tool="kismet",
                created_at=started_at,
                path=str(db_path),
                validation_status="complete",
                metadata={
                    "interfaces": interfaces,
                    "duration": duration,
                    "channels": list(channels or scan_result.channels_scanned),
                    "device_count": len(devices),
                },
            )
        ]
        if log_path.exists() and log_path.stat().st_size > 0:
            artifacts.append(
                EvidenceArtifact(
                    artifact_id=f"{stamp}-log",
                    kind="process_log",
                    source_tool="kismet",
                    created_at=started_at,
                    path=str(log_path),
                    validation_status="complete",
                    metadata={"interfaces": interfaces},
                )
            )

        return scan_result, artifacts

    def _select_interfaces(self) -> List[str]:
        """Select monitor-capable interfaces for capture."""
        if self.interface:
            return [self.interface]

        adapters = self.adapter_manager.discover_adapters()
        if not adapters:
            raise RuntimeError("No WiFi adapters found")

        optimal = self.adapter_manager.get_optimal_setup()
        monitor = optimal.get("monitor")
        interfaces = []

        if monitor:
            if not self.adapter_manager.enable_monitor_mode(monitor):
                raise RuntimeError(f"Failed to enable monitor mode on {monitor.interface}")
            interfaces.append(monitor.interface)

        # Add secondary adapter if available
        injection = optimal.get("injection")
        if injection and injection != monitor:
            if self.adapter_manager.enable_monitor_mode(injection):
                interfaces.append(injection.interface)

        if not interfaces:
            # Fallback: use first available adapter
            adapter = next((a for a in adapters if a.monitor_mode), adapters[0])
            if not self.adapter_manager.enable_monitor_mode(adapter):
                raise RuntimeError(f"Failed to enable monitor mode on {adapter.interface}")
            interfaces.append(adapter.interface)

        return interfaces

    def _wait_for_capture_window(self, process: subprocess.Popen, duration: int) -> None:
        """Wait for Kismet to start capturing, then wait for the survey duration."""
        # Use REST API to confirm Kismet is up and capturing
        client = KismetRestClient()
        startup_ok = client.wait_for_ready(timeout=30)

        if not startup_ok and process.poll() is not None:
            raise RuntimeError("Kismet exited before the survey window started")

        # Now wait for the actual capture duration
        capture_deadline = time.time() + max(duration, 1)
        while time.time() < capture_deadline:
            if process.poll() is not None:
                raise RuntimeError("Kismet exited before the survey window completed")
            time.sleep(1)

    def _stop_process(self, process: Optional[subprocess.Popen]) -> None:
        if not process or process.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=10)
        except Exception:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception:
                pass


__all__ = ["KismetSurveyProvider"]
