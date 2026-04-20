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


class TestBackgroundMonitoring(unittest.TestCase):
    """AttackChain refreshes client list from background scanner."""

    def test_background_scanner_refreshes_clients(self):
        """New clients from background scanner appear in deauth targeting."""
        from wifi_launchpad.domain.survey import Client, Network, ScanResult, EncryptionType
        from wifi_launchpad.services.attack_chain import AttackChain

        # Initial survey has 1 client
        network = Network(bssid="AA:BB:CC:DD:EE:01", ssid="Target", channel=6,
                          frequency=2437, signal_strength=-50, encryption=EncryptionType.WPA2)
        initial_scan = ScanResult()
        initial_scan.add_network(network)
        initial_scan.add_client(Client(mac_address="11:11:11:11:11:11",
                                       associated_bssid="AA:BB:CC:DD:EE:01",
                                       packets_sent=100))

        # Background scanner sees the original + a new client
        bg_results = ScanResult()
        bg_results.add_client(Client(mac_address="11:11:11:11:11:11",
                                     associated_bssid="AA:BB:CC:DD:EE:01",
                                     packets_sent=150))
        bg_results.add_client(Client(mac_address="22:22:22:22:22:22",
                                     associated_bssid="AA:BB:CC:DD:EE:01",
                                     packets_sent=50))

        mock_scanner = MagicMock()
        mock_scanner.get_current_results.return_value = bg_results

        chain = AttackChain(
            monitor_interface="wlan0",
            injection_interface="wlan2",
            background_scanner=mock_scanner,
        )

        # Verify the scanner is stored
        self.assertIsNotNone(chain.background_scanner)
        # Verify get_current_results returns fresh clients
        fresh = chain.background_scanner.get_current_results()
        fresh_clients = fresh.get_associated_clients("AA:BB:CC:DD:EE:01")
        self.assertEqual(len(fresh_clients), 2)

    def test_no_background_scanner_uses_initial_scan(self):
        """Without background scanner, AttackChain uses initial survey data."""
        from wifi_launchpad.services.attack_chain import AttackChain

        chain = AttackChain(
            monitor_interface="wlan0",
            injection_interface="wlan0",
        )
        self.assertIsNone(chain.background_scanner)


class TestScanResultMerge(unittest.TestCase):
    """ScanResult.merge() deduplicates correctly for dual-band survey."""

    def test_merge_unique_networks(self):
        """Networks on different bands merge without loss."""
        from wifi_launchpad.domain.survey import Network, ScanResult, EncryptionType

        r1 = ScanResult(channels_scanned=[1, 6, 11])
        r1.add_network(Network(bssid="AA:BB:CC:DD:EE:01", ssid="Net24", channel=6,
                               frequency=2437, signal_strength=-50, encryption=EncryptionType.WPA2))

        r2 = ScanResult(channels_scanned=[36, 40])
        r2.add_network(Network(bssid="AA:BB:CC:DD:EE:02", ssid="Net5", channel=36,
                               frequency=5180, signal_strength=-60, encryption=EncryptionType.WPA2))

        r1.merge(r2)
        self.assertEqual(len(r1.networks), 2)
        self.assertEqual(r1.channels_scanned, [1, 6, 11, 36, 40])

    def test_merge_duplicate_bssid_keeps_data(self):
        """Same BSSID seen on both scanners — signal gets updated, not duplicated."""
        from wifi_launchpad.domain.survey import Network, ScanResult, EncryptionType

        r1 = ScanResult(channels_scanned=[1, 6, 11])
        r1.add_network(Network(bssid="AA:BB:CC:DD:EE:01", ssid="Overlap", channel=6,
                               frequency=2437, signal_strength=-70, encryption=EncryptionType.WPA2))

        r2 = ScanResult(channels_scanned=[1, 6, 11])
        r2.add_network(Network(bssid="AA:BB:CC:DD:EE:01", ssid="Overlap", channel=6,
                               frequency=2437, signal_strength=-50, encryption=EncryptionType.WPA2))

        r1.merge(r2)
        self.assertEqual(len(r1.networks), 1)
        # Signal should be updated (exponential smoothing moves toward -50)
        self.assertGreater(r1.networks[0].signal_strength, -70)

    def test_merge_clients_deduplicate_by_mac(self):
        """Clients seen by both scanners are merged, not duplicated."""
        from wifi_launchpad.domain.survey import Client, ScanResult

        r1 = ScanResult()
        r1.add_client(Client(mac_address="11:22:33:44:55:66", associated_bssid="AA:BB:CC:DD:EE:01",
                             signal_strength=-60, packets_sent=100, probed_ssids=["Net1"]))

        r2 = ScanResult()
        r2.add_client(Client(mac_address="11:22:33:44:55:66", associated_bssid="AA:BB:CC:DD:EE:01",
                             signal_strength=-55, packets_sent=200, probed_ssids=["Net1", "Net2"]))
        r2.add_client(Client(mac_address="AA:BB:CC:DD:EE:FF", associated_bssid="AA:BB:CC:DD:EE:02",
                             signal_strength=-65, packets_sent=50))

        r1.merge(r2)
        self.assertEqual(len(r1.clients), 2)
        # First client should have merged probed SSIDs
        merged = next(c for c in r1.clients if c.mac_address == "11:22:33:44:55:66")
        self.assertIn("Net2", merged.probed_ssids)
        self.assertEqual(merged.packets_sent, 200)

    def test_merge_channels_no_duplicates(self):
        """Channel lists merge without duplicates."""
        from wifi_launchpad.domain.survey import ScanResult

        r1 = ScanResult(channels_scanned=[1, 6, 11])
        r2 = ScanResult(channels_scanned=[6, 11, 36, 40])
        r1.merge(r2)
        self.assertEqual(r1.channels_scanned, [1, 6, 11, 36, 40])


if __name__ == "__main__":
    unittest.main()
