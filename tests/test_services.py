#!/usr/bin/env python3
"""
Unit tests for service-layer orchestration.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock

from wifi_launchpad.domain.survey import EncryptionType, Network, ScanResult
from wifi_launchpad.services import CaptureService, ScanConfig, ScanMode, ScannerService


class TestScannerService(unittest.IsolatedAsyncioTestCase):
    """Test scanner service behavior around startup failures."""

    async def test_start_scan_returns_false_when_scanner_fails(self):
        service = ScannerService()
        service.scanner = MagicMock()
        service.scanner.start_scan.return_value = False

        started = await service.start_scan(ScanConfig(mode=ScanMode.DISCOVERY))

        self.assertFalse(started)
        self.assertFalse(service.is_running)


class TestCaptureService(unittest.IsolatedAsyncioTestCase):
    """Test targeted capture orchestration."""

    async def test_targeted_capture_passes_capture_timeout(self):
        service = CaptureService()
        target = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TargetNetwork",
            channel=6,
            frequency=2437,
            signal_strength=-42,
            encryption=EncryptionType.WPA2,
        )

        current_results = ScanResult(networks=[target])
        service.scanner = MagicMock()
        service.scanner.start_scan.return_value = True
        service.scanner.get_current_results.return_value = current_results
        service.scanner.stop_scan.return_value = current_results
        service.capture_target = AsyncMock(return_value=(True, {"bssid": target.bssid}))

        success, _ = await service.targeted_capture(
            ssid="TargetNetwork",
            scan_duration=1,
            capture_timeout=42,
        )

        self.assertTrue(success)
        service.capture_target.assert_awaited_once_with(
            target,
            42,
            requested_target="TargetNetwork",
            auto_selected=False,
        )

    async def test_targeted_capture_falls_back_to_available_target(self):
        service = CaptureService()
        fallback = Network(
            bssid="11:22:33:44:55:66",
            ssid="FallbackNetwork",
            channel=11,
            frequency=2462,
            signal_strength=-40,
            encryption=EncryptionType.WPA2,
        )

        current_results = ScanResult(networks=[fallback])
        service.scanner = MagicMock()
        service.scanner.start_scan.return_value = True
        service.scanner.get_current_results.return_value = ScanResult(networks=[])
        service.scanner.stop_scan.return_value = current_results
        service.capture_target = AsyncMock(return_value=(True, {"bssid": fallback.bssid, "auto_selected": True}))

        success, _ = await service.targeted_capture(
            ssid="MissingNetwork",
            scan_duration=1,
            capture_timeout=21,
        )

        self.assertTrue(success)
        service.capture_target.assert_awaited_once_with(
            fallback,
            21,
            requested_target="MissingNetwork",
            auto_selected=True,
        )

    async def test_capture_target_uses_hcx_when_requested(self):
        service = CaptureService(provider_preference="hcx")
        target = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TargetNetwork",
            channel=6,
            frequency=2437,
            signal_strength=-42,
            encryption=EncryptionType.WPA2,
        )
        service.hcx_provider = MagicMock()
        service.hcx_provider.capture_psk.return_value = (
            True,
            MagicMock(pcap_file="/tmp/capture.pcapng", quality_score=100.0, time_to_capture=12.0),
            "/tmp/capture.22000",
        )

        success, info = await service.capture_target(target, 30)

        self.assertTrue(success)
        self.assertEqual(info["provider"], "hcx")
        self.assertEqual(info["hash_file"], "/tmp/capture.22000")
