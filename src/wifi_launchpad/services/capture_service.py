"""Packaged capture workflow orchestration."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
import logging
from typing import Dict, List, Optional, Tuple

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.survey import Network, ScanResult
from wifi_launchpad.providers.external import HCXCaptureProvider
from wifi_launchpad.providers.native.adapters import AdapterManager
from wifi_launchpad.providers.native.capture import CaptureConfig, CaptureManager, DeauthController
from wifi_launchpad.providers.native.scanner import NetworkScanner
from wifi_launchpad.services.capture_backends import capture_with_hcx, resolve_capture_provider
from wifi_launchpad.services.capture_targeting import select_best_target

logger = logging.getLogger(__name__)


class WorkflowState(Enum):
    """Capture workflow states."""

    IDLE = "idle"
    SCANNING = "scanning"
    TARGET_SELECTED = "target_selected"
    CAPTURING = "capturing"
    SUCCESS = "success"
    FAILED = "failed"


class CaptureService:
    """Orchestrate scan, selection, and capture workflows."""

    def __init__(self, provider_preference: str = "auto") -> None:
        self.adapter_manager = AdapterManager()
        self.scanner: Optional[NetworkScanner] = None
        self.capture_manager: Optional[CaptureManager] = None
        self.deauth_controller: Optional[DeauthController] = None
        self.hcx_provider: Optional[HCXCaptureProvider] = None
        self.provider_preference = provider_preference
        self.state = WorkflowState.IDLE
        self.scan_results: Optional[ScanResult] = None
        self.target_network: Optional[Network] = None
        self.captured_handshakes: List[Dict] = []
        self.monitor_interface: Optional[str] = None
        self.injection_interface: Optional[str] = None

    async def initialize(self) -> bool:
        """Configure the best available adapter setup for capture."""

        try:
            adapters = self.adapter_manager.discover_adapters()
            if not adapters:
                logger.error("No WiFi adapters found")
                return False

            optimal = self.adapter_manager.get_optimal_setup()
            monitor_adapter = optimal.get("monitor")
            if not monitor_adapter:
                logger.error("No adapter suitable for monitoring")
                return False
            if not self.adapter_manager.enable_monitor_mode(monitor_adapter):
                logger.error("Failed to enable monitor mode on %s", monitor_adapter.interface)
                return False

            # When a second adapter is available, use it for dedicated injection
            # so the monitor adapter can listen without interruption (split mode)
            ap_adapter = optimal.get("ap")
            if ap_adapter and ap_adapter.monitor_mode:
                injection_adapter = ap_adapter
                self.adapter_manager.enable_monitor_mode(ap_adapter)
                logger.info("Split capture mode: monitor=%s, injection=%s",
                            monitor_adapter.interface, ap_adapter.interface)
            else:
                injection_adapter = optimal.get("injection") or monitor_adapter
            self.monitor_interface = monitor_adapter.interface
            self.injection_interface = injection_adapter.interface
            self.scanner = NetworkScanner(self.monitor_interface)
            self.capture_manager = CaptureManager(self.monitor_interface, self.injection_interface)
            self.deauth_controller = DeauthController(self.injection_interface)
            if HCXCaptureProvider.is_available():
                self.hcx_provider = HCXCaptureProvider(self.monitor_interface)
        except Exception as exc:
            logger.error("Failed to initialize capture service: %s", exc)
            return False

        logger.info(
            "Capture service initialized - Monitor: %s, Injection: %s",
            self.monitor_interface,
            self.injection_interface,
        )
        return True

    async def quick_capture(self, scan_duration: int = 30, capture_timeout: Optional[int] = None) -> Tuple[bool, Optional[Dict]]:
        """Scan, auto-select a target, and attempt capture."""
        capture_timeout = capture_timeout or get_settings().capture.timeout

        if not self.scanner and not await self.initialize():
            return False, None

        self.state = WorkflowState.SCANNING
        logger.info("Starting %ss network scan...", scan_duration)
        if not self.scanner.start_scan():
            logger.error("Failed to start scanner")
            self.state = WorkflowState.FAILED
            return False, None

        await asyncio.sleep(scan_duration)
        self.scan_results = self.scanner.stop_scan()
        if not self.scan_results.networks:
            logger.error("No networks found")
            self.state = WorkflowState.FAILED
            return False, None

        self.target_network = select_best_target(self.scan_results)
        if not self.target_network:
            logger.error("No suitable target found")
            self.state = WorkflowState.FAILED
            return False, None

        self.state = WorkflowState.TARGET_SELECTED
        logger.info("Selected target: %s (%s)", self.target_network.ssid, self.target_network.bssid)
        return await self.capture_target(self.target_network, capture_timeout)

    async def capture_target(
        self,
        network: Network,
        timeout: int = 300,
        requested_target: Optional[str] = None,
        auto_selected: bool = False,
    ) -> Tuple[bool, Optional[Dict]]:
        """Capture a handshake for a specific target network."""

        self.state = WorkflowState.CAPTURING
        self.target_network = network
        provider_name = resolve_capture_provider(self.provider_preference, self.hcx_provider, network)
        if provider_name == "hcx":
            success, _handshake, handshake_info = capture_with_hcx(
                self.hcx_provider,
                network=network,
                timeout=timeout,
                requested_target=requested_target,
                auto_selected=auto_selected,
            )
            if success and handshake_info:
                self.state = WorkflowState.SUCCESS
                self.captured_handshakes.append(handshake_info)
                logger.info("HCX capture produced hash artifact %s", handshake_info.get("hash_file"))
                return True, handshake_info
            # HCX failed — fall back to native deauth+handshake capture
            logger.warning("HCX capture failed, falling back to native capture")

        clients = self.scan_results.get_associated_clients(network.bssid) if self.scan_results else []
        config = CaptureConfig(
            target_bssid=network.bssid,
            target_channel=network.channel,
            target_ssid=network.ssid,
            capture_timeout=timeout,
            deauth_client=clients[0].mac_address if clients else None,
            deauth_count=10 if clients else 20,
        )
        logger.info("Starting handshake capture on %s", network.ssid)
        success, handshake = self.capture_manager.capture_handshake(config)
        if not success or not handshake:
            self.state = WorkflowState.FAILED
            logger.error("Failed to capture handshake")
            return False, None

        self.state = WorkflowState.SUCCESS
        handshake_info = {
            "network": network.ssid,
            "bssid": network.bssid,
            "file": handshake.pcap_file,
            "quality": handshake.quality_score,
            "capture_time": handshake.time_to_capture,
            "provider": provider_name,
            "hash_file": None,
            "requested_target": requested_target,
            "auto_selected": auto_selected,
        }
        self.captured_handshakes.append(handshake_info)
        logger.info("Handshake captured! Quality: %.1f", handshake.quality_score)
        return True, handshake_info

    async def targeted_capture(
        self,
        ssid: Optional[str] = None,
        bssid: Optional[str] = None,
        scan_duration: int = 60,
        capture_timeout: int = 300,
        no_fallback: bool = False,
    ) -> Tuple[bool, Optional[Dict]]:
        """Find a specific target by SSID or BSSID before capturing."""

        if not ssid and not bssid:
            logger.error("Either SSID or BSSID must be specified")
            return False, None
        if not self.scanner and not await self.initialize():
            return False, None

        self.state = WorkflowState.SCANNING
        logger.info("Searching for target: %s", ssid or bssid)
        if not self.scanner.start_scan():
            logger.error("Failed to start scanner")
            self.state = WorkflowState.FAILED
            return False, None

        target_found = None
        started = datetime.now()
        while (datetime.now() - started).total_seconds() < scan_duration:
            current = self.scanner.get_current_results()
            target_found = next(
                (
                    network
                    for network in current.networks
                    if (ssid and network.ssid == ssid) or (bssid and network.bssid == bssid)
                ),
                None,
            )
            if target_found:
                break
            await asyncio.sleep(2)

        requested_target = ssid or bssid
        auto_selected = False
        if not target_found:
            self.scan_results = self.scanner.stop_scan()
            if no_fallback:
                logger.info("Target %s not found (no_fallback=True)", requested_target)
                self.state = WorkflowState.FAILED
                return False, None
            target_found = select_best_target(self.scan_results)
            if not target_found:
                logger.error("Target not found and no suitable fallback target is available: %s", requested_target)
                self.state = WorkflowState.FAILED
                return False, None
            auto_selected = True
            logger.warning(
                "Target %s not found; falling back to available target %s (%s)",
                requested_target,
                target_found.ssid,
                target_found.bssid,
            )
        else:
            self.scan_results = self.scanner.stop_scan()
        return await self.capture_target(
            target_found,
            capture_timeout,
            requested_target=requested_target,
            auto_selected=auto_selected,
        )

    async def scan_only(self, duration: int = 60) -> ScanResult:
        """Perform a survey scan without a capture attempt."""

        if not self.scanner and not await self.initialize():
            return ScanResult()
        self.state = WorkflowState.SCANNING
        if not self.scanner.start_scan():
            self.state = WorkflowState.FAILED
            return ScanResult()
        await asyncio.sleep(duration)
        self.scan_results = self.scanner.stop_scan()
        self.state = WorkflowState.IDLE
        return self.scan_results

    def get_status(self) -> Dict:
        """Return current capture workflow status."""

        return {
            "state": self.state.value,
            "monitor_interface": self.monitor_interface,
            "injection_interface": self.injection_interface,
            "networks_found": len(self.scan_results.networks) if self.scan_results else 0,
            "current_target": self.target_network.ssid if self.target_network else None,
            "handshakes_captured": len(self.captured_handshakes),
        }

    def get_captured_handshakes(self) -> List[Dict]:
        """Return completed capture results."""

        return self.captured_handshakes

    async def cleanup(self) -> None:
        """Stop active tooling and restore managed mode."""

        if self.scanner and self.scanner.is_scanning:
            self.scanner.stop_scan()
        if self.capture_manager:
            self.capture_manager.stop()
        if self.adapter_manager and self.monitor_interface:
            for adapter in self.adapter_manager.discover_adapters():
                if adapter.interface == self.monitor_interface:
                    self.adapter_manager.disable_monitor_mode(adapter)
        self.state = WorkflowState.IDLE
        logger.info("Capture service cleaned up")
