"""Multi-tool survey pipeline — runs available tools in phases.

Phase 1: Kismet (primary passive recon)
Phase 2: wash (WPS detection)
Phase 3: airodump-ng (client enrichment)
Phase 4: tshark (traffic analysis)

Each phase is optional — gracefully skipped if the tool is missing.
Results from all phases merge into a single ScanResult.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Callable, List, Optional

from wifi_launchpad.domain.survey import ScanResult

logger = logging.getLogger(__name__)


class SurveyPipeline:
    """Orchestrate multi-phase WiFi survey using best available tools."""

    def __init__(self, interface: str, on_phase: Optional[Callable] = None) -> None:
        self.interface = interface
        self.on_phase = on_phase or (lambda name, status: None)

    async def run(self, duration: int = 90) -> ScanResult:
        """Run all available survey phases and return merged result."""
        result = ScanResult()

        # Phase 1: Kismet (primary recon)
        kismet_ok = False
        if self._has("kismet"):
            self.on_phase("Kismet survey", "starting")
            kismet_result = await self._run_kismet(duration)
            if kismet_result and kismet_result.networks:
                result.merge(kismet_result)
                kismet_ok = True
                self.on_phase("Kismet survey", f"done — {len(kismet_result.networks)} networks")
            else:
                self.on_phase("Kismet survey", "failed — falling back to airodump-ng")

        if not kismet_ok:
            # Full-duration airodump as primary scan
            label = "airodump-ng survey" + (" (Kismet failed)" if self._has("kismet") else "")
            self.on_phase(label, f"starting ({duration}s)")
            airo_result = await self._run_airodump(duration)
            if airo_result:
                result.merge(airo_result)
                self.on_phase(label, f"done — {len(airo_result.networks)} networks")

        # Phase 2: wash (WPS detection)
        if self._has("wash"):
            self.on_phase("wash WPS scan", "starting")
            from wifi_launchpad.providers.external.wash_wps import scan_wps, merge_wps_into_networks
            wps_results = await scan_wps(self.interface, timeout=15)
            merged = merge_wps_into_networks(result.networks, wps_results)
            self.on_phase("wash WPS scan", f"done — {merged} WPS APs detected")

        # Phase 3: airodump-ng client enrichment (only if Kismet was primary)
        if kismet_ok and self._has("airodump-ng"):
            self.on_phase("airodump-ng client pass", "starting (30s)")
            airo_result = await self._run_airodump(30)
            if airo_result:
                result.merge(airo_result)
                self.on_phase("airodump-ng client pass", f"done — {len(airo_result.clients)} clients")

        # Phase 4: tshark traffic analysis
        if self._has("tshark"):
            self.on_phase("tshark traffic analysis", "starting")
            observations = await self._run_tshark(min(duration, 60))
            self.on_phase("tshark traffic analysis", f"done — {len(observations)} observations")
            # Store observations on result for DB persistence
            result._traffic_observations = observations  # type: ignore[attr-defined]

        return result

    def _has(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    async def _run_kismet(self, duration: int) -> Optional[ScanResult]:
        try:
            from wifi_launchpad.providers.external.kismet import KismetSurveyProvider
            provider = KismetSurveyProvider(interface=self.interface)
            # run_survey is synchronous — run in thread to avoid blocking the event loop
            result, _artifacts = await asyncio.to_thread(
                provider.run_survey, duration=duration,
            )
            return result
        except Exception as exc:
            logger.debug("Kismet survey failed: %s", exc)
            return None

    async def _run_airodump(self, duration: int) -> Optional[ScanResult]:
        try:
            from wifi_launchpad.providers.native.scanner.network_scanner import NetworkScanner
            scanner = NetworkScanner(interface=self.interface)
            scanner.start_scan(write_interval=2)
            await asyncio.sleep(duration)
            return scanner.stop_scan()
        except Exception as exc:
            logger.debug("airodump-ng survey failed: %s", exc)
            return None

    async def _run_tshark(self, duration: int) -> List[dict]:
        """Run tshark live capture for protocol/traffic analysis."""
        try:
            cmd = [
                "sudo", "tshark", "-i", self.interface, "-a", f"duration:{duration}",
                "-Y", "http || dns || ftp || telnet",
                "-T", "fields", "-e", "wlan.bssid", "-e", "_ws.col.Protocol",
                "-e", "_ws.col.Info",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            return _parse_tshark_traffic(stdout.decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.debug("tshark traffic analysis failed: %s", exc)
            return []


def _parse_tshark_traffic(output: str) -> List[dict]:
    """Parse tshark field output into traffic observations."""
    observations: list[dict] = []
    for line in output.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        bssid, protocol, detail = parts[0], parts[1], parts[2]
        cleartext = protocol.upper() in ("HTTP", "FTP", "TELNET")
        observations.append({
            "bssid": bssid or None,
            "protocol": protocol,
            "detail": detail[:500],
            "cleartext": cleartext,
        })
    return observations


__all__ = ["SurveyPipeline"]
