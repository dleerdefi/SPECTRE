#!/usr/bin/env python3
"""
Unit tests for the scanner module

Tests models, parser, and scanner functionality with mock data.
"""

import unittest
import tempfile
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from wifi_launchpad.domain.capture import Handshake
from wifi_launchpad.domain.survey import Client, EncryptionType, Network, ScanResult, WiFiBand
from wifi_launchpad.providers.native.scanner import AirodumpParser, NetworkScanner


class TestNetworkModel(unittest.TestCase):
    """Test Network model functionality"""

    def test_network_creation(self):
        """Test creating a network instance"""
        network = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            channel=6,
            frequency=2437,
            signal_strength=-45,
            encryption=EncryptionType.WPA2
        )

        self.assertEqual(network.bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(network.ssid, "TestNetwork")
        self.assertEqual(network.channel, 6)
        self.assertEqual(network.signal_strength, -45)
        self.assertEqual(network.encryption, EncryptionType.WPA2)

    def test_network_equality(self):
        """Test network equality based on BSSID"""
        network1 = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="Network1",
            channel=1,
            frequency=2412,
            signal_strength=-50,
            encryption=EncryptionType.WPA2
        )
        network2 = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="Network2",
            channel=6,
            frequency=2437,
            signal_strength=-60,
            encryption=EncryptionType.WPA
        )
        network3 = Network(
            bssid="11:22:33:44:55:66",
            ssid="Network3",
            channel=1,
            frequency=2412,
            signal_strength=-50,
            encryption=EncryptionType.WPA2
        )

        self.assertEqual(network1, network2)  # Same BSSID
        self.assertNotEqual(network1, network3)  # Different BSSID

    def test_signal_update(self):
        """Test signal strength smoothing"""
        network = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            channel=6,
            frequency=2437,
            signal_strength=-50,
            encryption=EncryptionType.WPA2
        )

        # Update signal
        network.update_signal(-40)
        # Should be smoothed: 0.3 * -40 + 0.7 * -50 = -47
        self.assertEqual(network.signal_strength, -47)

    def test_network_serialization(self):
        """Test network to_dict conversion"""
        network = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            channel=6,
            frequency=2437,
            signal_strength=-45,
            encryption=EncryptionType.WPA2,
            wps_enabled=True
        )

        data = network.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(data["ssid"], "TestNetwork")
        self.assertEqual(data["encryption"], "WPA2")
        self.assertTrue(data["wps_enabled"])


class TestClientModel(unittest.TestCase):
    """Test Client model functionality"""

    def test_client_creation(self):
        """Test creating a client instance"""
        client = Client(
            mac_address="11:22:33:44:55:66",
            associated_bssid="AA:BB:CC:DD:EE:FF"
        )

        self.assertEqual(client.mac_address, "11:22:33:44:55:66")
        self.assertEqual(client.associated_bssid, "AA:BB:CC:DD:EE:FF")

    def test_probe_management(self):
        """Test adding probe requests"""
        client = Client(mac_address="11:22:33:44:55:66")

        client.add_probe("Network1")
        client.add_probe("Network2")
        client.add_probe("Network1")  # Duplicate

        self.assertEqual(len(client.probed_ssids), 2)
        self.assertIn("Network1", client.probed_ssids)
        self.assertIn("Network2", client.probed_ssids)


class TestHandshakeModel(unittest.TestCase):
    """Test Handshake model functionality"""

    def test_handshake_validation(self):
        """Test handshake validation logic"""
        handshake = Handshake(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            client_mac="11:22:33:44:55:66",
            pcap_file="/tmp/capture.pcap",
            file_size=1024
        )

        # Invalid - no EAPOL packets
        self.assertFalse(handshake.validate())
        self.assertEqual(handshake.quality_score, 0)

        # Valid - M1 and M2 present
        handshake.m1_present = True
        handshake.m2_present = True
        handshake.eapol_packets = 4
        self.assertTrue(handshake.validate())
        self.assertTrue(handshake.is_complete)
        self.assertGreater(handshake.quality_score, 0)


class TestAirodumpParser(unittest.TestCase):
    """Test airodump-ng CSV parser"""

    def setUp(self):
        self.parser = AirodumpParser()

    def test_parse_network_csv(self):
        """Test parsing network data from CSV"""
        csv_content = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2024-01-15 10:00:00, 2024-01-15 10:05:00, 6, 54, WPA2, CCMP, PSK, -45, 100, 0, 0.0.0.0, 11, TestNetwork,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            temp_file = f.name

        try:
            result = self.parser.parse_csv_file(temp_file)
            self.assertEqual(len(result.networks), 1)

            network = result.networks[0]
            self.assertEqual(network.bssid, "AA:BB:CC:DD:EE:FF")
            self.assertEqual(network.ssid, "TestNetwork")
            self.assertEqual(network.channel, 6)
            self.assertEqual(network.signal_strength, -45)
            self.assertEqual(network.encryption, EncryptionType.WPA2)
        finally:
            Path(temp_file).unlink()

    def test_parse_client_csv(self):
        """Test parsing client data from CSV"""
        csv_content = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-15 10:00:00, 2024-01-15 10:05:00, -50, 42, AA:BB:CC:DD:EE:FF, Network1,Network2
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            temp_file = f.name

        try:
            result = self.parser.parse_csv_file(temp_file)
            self.assertEqual(len(result.clients), 1)

            client = result.clients[0]
            self.assertEqual(client.mac_address, "11:22:33:44:55:66")
            self.assertEqual(client.associated_bssid, "AA:BB:CC:DD:EE:FF")
            self.assertEqual(client.signal_strength, -50)
            self.assertIn("Network1", client.probed_ssids)
            self.assertIn("Network2", client.probed_ssids)
        finally:
            Path(temp_file).unlink()

    def test_encryption_detection(self):
        """Test encryption type detection"""
        test_cases = [
            ("WPA2", "CCMP", "PSK", EncryptionType.WPA2),
            ("WPA", "TKIP", "PSK", EncryptionType.WPA),
            ("WEP", "", "", EncryptionType.WEP),
            ("OPN", "", "", EncryptionType.OPEN),
            ("WPA2 WPA", "CCMP TKIP", "PSK", EncryptionType.WPA_WPA2),
            ("WPA2", "CCMP", "802.1X", EncryptionType.ENTERPRISE),
        ]

        for privacy, cipher, auth, expected in test_cases:
            result = self.parser._parse_encryption(privacy, cipher, auth)
            self.assertEqual(result, expected, f"Failed for {privacy}/{cipher}/{auth}")

    def test_mac_validation(self):
        """Test MAC address validation"""
        valid_macs = [
            "AA:BB:CC:DD:EE:FF",
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF"
        ]
        invalid_macs = [
            "AA:BB:CC:DD:EE",  # Too short
            "AA:BB:CC:DD:EE:FF:00",  # Too long
            "AABBCCDDEEFF",  # No separators
            "ZZ:BB:CC:DD:EE:FF",  # Invalid hex
            "",  # Empty
        ]

        for mac in valid_macs:
            self.assertTrue(self.parser._is_valid_mac(mac), f"{mac} should be valid")

        for mac in invalid_macs:
            self.assertFalse(self.parser._is_valid_mac(mac), f"{mac} should be invalid")

    def test_filters_invalid_noise_rows(self):
        """Test dropping bogus network and client rows with invalid signal data."""

        network_row = [
            "78:28:CA:9F:94:93",
            "2024-01-15 10:00:00",
            "2024-01-15 10:05:00",
            "11",
            "54",
            "WPA",
            "",
            "",
            "-1",
            "0",
            "0",
            "0.0.0.0",
            "0",
            "",
            "",
        ]
        client_row = [
            "10:33:BF:6C:86:3F",
            "2024-01-15 10:00:00",
            "2024-01-15 10:05:00",
            "-1",
            "2",
            "10:33:BF:6C:86:3F",
            "",
        ]

        self.assertIsNone(self.parser._parse_network_row(network_row))
        self.assertIsNone(self.parser._parse_client_row(client_row))


class TestScanResult(unittest.TestCase):
    """Test ScanResult container"""

    def test_add_network(self):
        """Test adding and updating networks"""
        result = ScanResult()

        network1 = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="Network1",
            channel=1,
            frequency=2412,
            signal_strength=-50,
            encryption=EncryptionType.WPA2
        )

        # Add new network
        result.add_network(network1)
        self.assertEqual(len(result.networks), 1)

        # Update existing network
        network2 = Network(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="Network1",
            channel=1,
            frequency=2412,
            signal_strength=-40,
            encryption=EncryptionType.WPA2
        )
        result.add_network(network2)
        self.assertEqual(len(result.networks), 1)  # Still 1 network

    def test_get_associated_clients(self):
        """Test getting clients associated with a network"""
        result = ScanResult()

        client1 = Client(
            mac_address="11:22:33:44:55:66",
            associated_bssid="AA:BB:CC:DD:EE:FF"
        )
        client2 = Client(
            mac_address="77:88:99:AA:BB:CC",
            associated_bssid="AA:BB:CC:DD:EE:FF"
        )
        client3 = Client(
            mac_address="DD:EE:FF:00:11:22",
            associated_bssid="11:22:33:44:55:66"
        )

        result.add_client(client1)
        result.add_client(client2)
        result.add_client(client3)

        associated = result.get_associated_clients("AA:BB:CC:DD:EE:FF")
        self.assertEqual(len(associated), 2)
        self.assertIn(client1, associated)
        self.assertIn(client2, associated)
        self.assertNotIn(client3, associated)


class TestNetworkScanner(unittest.TestCase):
    """Test NetworkScanner functionality"""

    @patch('subprocess.Popen')
    @patch('subprocess.run')
    def test_scanner_initialization(self, mock_run, mock_popen):
        """Test scanner initialization"""
        scanner = NetworkScanner("wlan0mon")
        self.assertEqual(scanner.interface, "wlan0mon")
        self.assertIsNotNone(scanner.parser)
        self.assertFalse(scanner.is_scanning)

    @patch('subprocess.run')
    @patch('subprocess.Popen')
    def test_scanner_passes_requested_channels_to_airodump(self, mock_popen, mock_run):
        """Test explicit scan channels are passed through to airodump-ng."""

        mock_run.return_value = MagicMock(returncode=0)
        mock_popen.return_value = MagicMock()
        scanner = NetworkScanner("wlan0mon")

        started = scanner.start_scan(channels=[3, 4, 5], write_interval=2)

        self.assertTrue(started)
        cmd = mock_popen.call_args.args[0]
        self.assertIn("--channel", cmd)
        self.assertIn("3,4,5", cmd)
        scanner.is_scanning = False

    @patch('subprocess.run')
    def test_set_channel(self, mock_run):
        """Test channel setting"""
        mock_run.return_value = MagicMock(returncode=0)

        scanner = NetworkScanner("wlan0mon")
        result = scanner.set_channel(6)

        self.assertTrue(result)
        self.assertEqual(scanner.current_channel, 6)
        mock_run.assert_called_once()

    def test_channel_strategy(self):
        """Test channel strategy configuration"""
        scanner = NetworkScanner("wlan0mon")

        scanner.set_channel_strategy(
            mode="adaptive",
            dwell_time=3.0,
            priority_channels={1: 2.0, 6: 1.5, 11: 1.0}
        )

        self.assertEqual(scanner.channel_strategy.mode, "adaptive")
        self.assertEqual(scanner.channel_strategy.dwell_time, 3.0)
        self.assertEqual(scanner.channel_strategy.priority_channels[1], 2.0)


if __name__ == '__main__':
    unittest.main()
