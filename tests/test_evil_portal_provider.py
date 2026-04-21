#!/usr/bin/env python3
"""Unit tests for the evil portal provider."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from wifi_launchpad.domain.evil_portal import PortalConfig, PortalSession, PortalStatus
from wifi_launchpad.providers.external.evil_portal import EvilPortalProvider


class TestAvailabilityChecks(unittest.TestCase):
    """Static availability detection."""

    @patch("wifi_launchpad.providers.external.evil_portal.shutil.which")
    def test_is_available_both_present(self, mock_which):
        mock_which.side_effect = lambda x: f"/usr/sbin/{x}"
        self.assertTrue(EvilPortalProvider.is_available())

    @patch("wifi_launchpad.providers.external.evil_portal.shutil.which")
    def test_is_available_missing_dnsmasq(self, mock_which):
        mock_which.side_effect = lambda x: "/usr/sbin/hostapd" if x == "hostapd" else None
        self.assertFalse(EvilPortalProvider.is_available())

    @patch("wifi_launchpad.providers.external.evil_portal.shutil.which")
    def test_has_mana(self, mock_which):
        mock_which.return_value = "/usr/sbin/hostapd-mana"
        self.assertTrue(EvilPortalProvider.has_mana())

    @patch("wifi_launchpad.providers.external.evil_portal.shutil.which")
    def test_has_mana_not_installed(self, mock_which):
        mock_which.return_value = None
        self.assertFalse(EvilPortalProvider.has_mana())


class TestConfigGeneration(unittest.TestCase):
    """Config file generation for hostapd and dnsmasq."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.provider = EvilPortalProvider(output_dir=Path(self.tmpdir))
        self.config = PortalConfig(
            target_ssid="FreeWiFi",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_channel=6,
            ap_interface="wlan2",
            deauth_interface="wlan0",
            gateway_ip="192.169.254.1",
            dhcp_range_start="192.169.254.50",
            dhcp_range_end="192.169.254.200",
            subnet_mask="255.255.255.0",
        )

    def test_hostapd_conf_24ghz(self):
        path = self.provider.configure_hostapd(self.config)
        content = path.read_text()
        self.assertIn("interface=wlan2", content)
        self.assertIn("ssid=FreeWiFi", content)
        self.assertIn("channel=6", content)
        self.assertIn("hw_mode=g", content)
        self.assertIn("driver=nl80211", content)
        self.assertNotIn("ieee80211d", content)

    def test_hostapd_conf_5ghz(self):
        self.config.target_channel = 36
        path = self.provider.configure_hostapd(self.config)
        content = path.read_text()
        self.assertIn("hw_mode=a", content)
        self.assertIn("channel=36", content)
        self.assertIn("ieee80211d=1", content)

    @patch("wifi_launchpad.providers.external.evil_portal.EvilPortalProvider.has_mana", return_value=True)
    def test_hostapd_conf_mana(self, _):
        self.config.use_mana = True
        path = self.provider.configure_hostapd(self.config)
        content = path.read_text()
        self.assertIn("enable_mana=1", content)
        self.assertIn("mana_loud=1", content)

    @patch("wifi_launchpad.providers.external.evil_portal.get_settings")
    def test_dnsmasq_conf_with_option_114(self, mock_settings):
        mock_ep = MagicMock()
        mock_ep.use_dhcp_option_114 = True
        mock_settings.return_value.evil_portal = mock_ep
        mock_settings.return_value.temp_dir = Path(self.tmpdir)

        path = self.provider.configure_dnsmasq(self.config)
        content = path.read_text()
        self.assertIn("interface=wlan2", content)
        self.assertIn("listen-address=192.169.254.1", content)
        self.assertIn("dhcp-range=192.169.254.50,192.169.254.200", content)
        self.assertIn("dhcp-option=3,192.169.254.1", content)
        self.assertIn("dhcp-option=6,192.169.254.1", content)
        self.assertIn("dhcp-option=114,http://192.169.254.1/portal", content)
        self.assertIn("address=/#/192.169.254.1", content)

    @patch("wifi_launchpad.providers.external.evil_portal.get_settings")
    def test_dnsmasq_conf_without_option_114(self, mock_settings):
        mock_ep = MagicMock()
        mock_ep.use_dhcp_option_114 = False
        mock_settings.return_value.evil_portal = mock_ep
        mock_settings.return_value.temp_dir = Path(self.tmpdir)

        path = self.provider.configure_dnsmasq(self.config)
        content = path.read_text()
        self.assertNotIn("dhcp-option=114", content)


class TestIptables(unittest.TestCase):
    """Iptables setup calls correct commands."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.provider = EvilPortalProvider(output_dir=Path(self.tmpdir))
        self.config = PortalConfig(
            target_ssid="Test", target_bssid="AA:BB:CC:DD:EE:FF",
            target_channel=6, ap_interface="wlan2",
            gateway_ip="192.169.254.1",
            dhcp_range_start="192.169.254.50", dhcp_range_end="192.169.254.200",
            subnet_mask="255.255.255.0",
        )

    @patch("wifi_launchpad.providers.external.evil_portal.subprocess.run")
    def test_setup_iptables_calls_save_and_rules(self, mock_run):
        mock_run.return_value = MagicMock(stdout="# iptables backup", returncode=0)
        result = self.provider.setup_iptables(self.config)
        self.assertTrue(result)
        # First call should be iptables-save
        first_call = mock_run.call_args_list[0]
        self.assertEqual(first_call.args[0][:2], ["sudo", "iptables-save"])
        # Should have the DNAT rule for port 80
        all_cmds = [c.args[0] for c in mock_run.call_args_list]
        dnat_found = any("DNAT" in cmd and "80" in cmd for cmd in all_cmds)
        self.assertTrue(dnat_found)


class TestTeardown(unittest.TestCase):
    """Teardown calls stop + restore in correct order."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.provider = EvilPortalProvider(output_dir=Path(self.tmpdir))

    @patch("wifi_launchpad.providers.external.evil_portal.subprocess.run")
    @patch("wifi_launchpad.providers.external.evil_portal.os.killpg")
    @patch("wifi_launchpad.providers.external.evil_portal.os.waitpid")
    def test_teardown_stops_processes_and_restores(self, mock_wait, mock_killpg, mock_run):
        config = PortalConfig(
            target_ssid="Test", target_bssid="AA:BB:CC:DD:EE:FF",
            target_channel=6, ap_interface="wlan2",
            gateway_ip="192.169.254.1",
            dhcp_range_start="192.169.254.50", dhcp_range_end="192.169.254.200",
            subnet_mask="255.255.255.0",
        )
        session = PortalSession(
            session_id="test-001", config=config, status=PortalStatus.ACTIVE,
            hostapd_pid=1001, dnsmasq_pid=1002, deauth_pid=1003,
        )
        # Create fake backup so restore doesn't fail
        backup = Path(self.tmpdir) / "iptables.backup"
        backup.write_text("# backup", encoding="utf-8")
        self.provider._iptables_backup = backup
        self.provider._original_ip_forward = "0"

        self.provider.teardown(session)

        # Should have tried to kill all 3 PIDs
        killed_pids = [c.args[0] for c in mock_killpg.call_args_list]
        self.assertIn(1003, killed_pids)  # deauth first
        self.assertIn(1002, killed_pids)  # dnsmasq
        self.assertIn(1001, killed_pids)  # hostapd


if __name__ == "__main__":
    unittest.main()
