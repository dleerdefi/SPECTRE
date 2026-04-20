#!/usr/bin/env python3
"""
Unit tests for dual-adapter operational modes.

Tests that split capture mode activates when a second adapter is available,
and that single-adapter setups remain unchanged.
"""

import asyncio
import unittest
from unittest.mock import MagicMock, patch

from wifi_launchpad.providers.native.adapters.models import WifiAdapter
from wifi_launchpad.providers.native.adapters.manager import AdapterManager


def _make_adapter(interface, chipset, driver, monitor=True, injection=True, bands=None, mode="managed"):
    adapter = WifiAdapter(
        interface=interface,
        mac_address=f"00:11:22:33:44:{interface[-1:].zfill(2)}",
        phy=f"phy{interface[-1:]}",
        driver=driver,
        chipset=chipset,
        monitor_mode=monitor,
        packet_injection=injection,
        frequency_bands=bands or ["2.4GHz", "5GHz"],
        current_mode=mode,
    )
    return adapter


class TestSplitCaptureWiring(unittest.TestCase):
    """CaptureService uses separate interfaces when AP adapter is available."""

    @patch("wifi_launchpad.services.capture_service.HCXCaptureProvider")
    @patch("wifi_launchpad.services.capture_service.DeauthController")
    @patch("wifi_launchpad.services.capture_service.CaptureManager")
    @patch("wifi_launchpad.services.capture_service.NetworkScanner")
    @patch("wifi_launchpad.services.capture_service.AdapterManager")
    def test_split_mode_with_two_adapters(self, MockMgr, MockScanner, MockCapture, MockDeauth, MockHCX):
        """Two RTL8812AU adapters -> split monitor/injection interfaces."""
        from wifi_launchpad.services.capture_service import CaptureService

        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        rtl2 = _make_adapter("wlan2", "RTL8812AU", "88XXau")
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)

        mock_mgr = MockMgr.return_value
        mock_mgr.discover_adapters.return_value = [rtl1, qca, rtl2]
        mock_mgr.get_optimal_setup.return_value = {
            "monitor": rtl1,
            "injection": rtl1,
            "management": qca,
            "ap": rtl2,
        }
        mock_mgr.enable_monitor_mode.return_value = True
        MockHCX.is_available.return_value = False

        service = CaptureService()
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(service.initialize())
        loop.close()

        self.assertTrue(result)
        self.assertEqual(service.monitor_interface, "wlan0")
        self.assertEqual(service.injection_interface, "wlan2")
        # Verify monitor mode enabled on both adapters
        calls = mock_mgr.enable_monitor_mode.call_args_list
        interfaces_enabled = [call.args[0].interface for call in calls]
        self.assertIn("wlan0", interfaces_enabled)
        self.assertIn("wlan2", interfaces_enabled)

    @patch("wifi_launchpad.services.capture_service.HCXCaptureProvider")
    @patch("wifi_launchpad.services.capture_service.DeauthController")
    @patch("wifi_launchpad.services.capture_service.CaptureManager")
    @patch("wifi_launchpad.services.capture_service.NetworkScanner")
    @patch("wifi_launchpad.services.capture_service.AdapterManager")
    def test_single_adapter_fallback(self, MockMgr, MockScanner, MockCapture, MockDeauth, MockHCX):
        """One RTL8812AU -> same interface for both monitor and injection."""
        from wifi_launchpad.services.capture_service import CaptureService

        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)

        mock_mgr = MockMgr.return_value
        mock_mgr.discover_adapters.return_value = [rtl1, qca]
        mock_mgr.get_optimal_setup.return_value = {
            "monitor": rtl1,
            "injection": rtl1,
            "management": qca,
            "ap": None,
        }
        mock_mgr.enable_monitor_mode.return_value = True
        MockHCX.is_available.return_value = False

        service = CaptureService()
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(service.initialize())
        loop.close()

        self.assertTrue(result)
        self.assertEqual(service.monitor_interface, "wlan0")
        self.assertEqual(service.injection_interface, "wlan0")

    @patch("wifi_launchpad.services.capture_service.HCXCaptureProvider")
    @patch("wifi_launchpad.services.capture_service.DeauthController")
    @patch("wifi_launchpad.services.capture_service.CaptureManager")
    @patch("wifi_launchpad.services.capture_service.NetworkScanner")
    @patch("wifi_launchpad.services.capture_service.AdapterManager")
    def test_ap_adapter_not_in_monitor_falls_back(self, MockMgr, MockScanner, MockCapture, MockDeauth, MockHCX):
        """AP adapter in managed mode (e.g., running evil portal) -> single adapter fallback."""
        from wifi_launchpad.services.capture_service import CaptureService

        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        rtl2 = _make_adapter("wlan2", "RTL8812AU", "88XXau", monitor=False)  # AP mode, not monitor-capable right now
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)

        mock_mgr = MockMgr.return_value
        mock_mgr.discover_adapters.return_value = [rtl1, qca, rtl2]
        mock_mgr.get_optimal_setup.return_value = {
            "monitor": rtl1,
            "injection": rtl1,
            "management": qca,
            "ap": rtl2,
        }
        mock_mgr.enable_monitor_mode.return_value = True
        MockHCX.is_available.return_value = False

        service = CaptureService()
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(service.initialize())
        loop.close()

        self.assertTrue(result)
        # AP adapter has monitor=False, so falls back to single adapter
        self.assertEqual(service.monitor_interface, "wlan0")
        self.assertEqual(service.injection_interface, "wlan0")


if __name__ == "__main__":
    unittest.main()
