"""Tests for Kismet DB reader and device-to-domain mapper."""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from wifi_launchpad.domain.survey import EncryptionType, WiFiBand
from wifi_launchpad.providers.external.kismet_client import KismetDbReader, find_kismet_db
from wifi_launchpad.providers.external.kismet_mapper import (
    _parse_kismet_crypt,
    map_devices_to_scan_result,
)

# ── Sample Kismet device JSON blobs ─────────────────────────────────────

SAMPLE_AP = {
    "kismet.device.base.macaddr": "0A:58:28:16:14:7A",
    "kismet.device.base.name": "QF-1110",
    "kismet.device.base.crypt": "WPA3 WPA3-PSK WPA3-SAE AES-CCMP",
    "kismet.device.base.channel": "48",
    "kismet.device.base.frequency": 5240000,
    "kismet.device.base.manuf": "Unknown",
    "kismet.device.base.first_time": 1776131292,
    "kismet.device.base.last_time": 1776131299,
    "kismet.device.base.packets.total": 10,
    "kismet.device.base.signal": {
        "kismet.common.signal.last_signal": -23,
        "kismet.common.signal.max_signal": -23,
    },
    "dot11.device": {
        "dot11.device.last_bssid": "0A:58:28:16:14:7A",
        "dot11.device.num_associated_clients": 6,
        "dot11.device.advertised_ssid_map": [
            {
                "dot11.advertisedssid.ssid": "QF-1110",
                "dot11.advertisedssid.cloaked": 0,
                "dot11.advertisedssid.channel": "48",
                "dot11.advertisedssid.beaconrate": 10,
                "dot11.advertisedssid.ht_mode": "HT80",
            }
        ],
        "dot11.device.probed_ssid_map": [],
    },
}

SAMPLE_CLIENT = {
    "kismet.device.base.macaddr": "56:96:B9:6A:D5:6A",
    "kismet.device.base.name": "",
    "kismet.device.base.crypt": "",
    "kismet.device.base.channel": "",
    "kismet.device.base.frequency": 0,
    "kismet.device.base.manuf": "Apple",
    "kismet.device.base.first_time": 1776131293,
    "kismet.device.base.last_time": 1776131293,
    "kismet.device.base.packets.total": 2,
    "kismet.device.base.packets.tx_total": 0,
    "kismet.device.base.packets.rx_total": 2,
    "kismet.device.base.signal": {
        "kismet.common.signal.last_signal": -45,
    },
    "dot11.device": {
        "dot11.device.last_bssid": "50:BA:7D:5A:8D:1F",
        "dot11.device.probed_ssid_map": [
            {"dot11.probedssid.ssid": "HomeNetwork"},
            {"dot11.probedssid.ssid": "CoffeeShop"},
        ],
    },
}


# ── Crypt parsing ───────────────────────────────────────────────────────


class TestKismetCryptParsing:
    def test_wpa3_sae(self):
        enc, cipher, auth = _parse_kismet_crypt("WPA3 WPA3-PSK WPA3-SAE AES-CCMP")
        assert enc == EncryptionType.WPA3
        assert "CCMP" in cipher
        assert "SAE" in auth

    def test_wpa2_psk(self):
        enc, cipher, auth = _parse_kismet_crypt("WPA2-PSK AES-CCMP")
        assert enc == EncryptionType.WPA2
        assert "CCMP" in cipher
        assert "PSK" in auth

    def test_enterprise(self):
        enc, cipher, auth = _parse_kismet_crypt("WPA2-EAP AES-CCMP")
        assert enc == EncryptionType.ENTERPRISE

    def test_open(self):
        enc, cipher, auth = _parse_kismet_crypt("None")
        assert enc == EncryptionType.OPEN

    def test_empty(self):
        enc, cipher, auth = _parse_kismet_crypt("")
        assert enc == EncryptionType.OPEN

    def test_wpa_wpa2_mixed(self):
        enc, cipher, auth = _parse_kismet_crypt("WPA-PSK WPA2-PSK TKIP AES-CCMP")
        assert enc == EncryptionType.WPA_WPA2

    def test_wep(self):
        enc, cipher, auth = _parse_kismet_crypt("WEP")
        assert enc == EncryptionType.WEP


# ── Device mapping ──────────────────────────────────────────────────────


class TestKismetMapper:
    def test_map_ap_to_network(self):
        devices = [{"devmac": "0A:58:28:16:14:7A", "type": "Wi-Fi AP",
                     "strongest_signal": -23, "first_time": 1776131292,
                     "last_time": 1776131299, "device": SAMPLE_AP}]
        result = map_devices_to_scan_result(devices)
        assert len(result.networks) == 1
        net = result.networks[0]
        assert net.bssid == "0A:58:28:16:14:7A"
        assert net.ssid == "QF-1110"
        assert net.channel == 48
        assert net.signal_strength == -23
        assert net.encryption == EncryptionType.WPA3
        assert net.band == WiFiBand.BAND_5GHZ
        assert net.beacon_rate == 10
        assert net.wifi_standard == "HT80"

    def test_map_client(self):
        devices = [{"devmac": "56:96:B9:6A:D5:6A", "type": "Wi-Fi Client",
                     "strongest_signal": -45, "first_time": 1776131293,
                     "last_time": 1776131293, "device": SAMPLE_CLIENT}]
        result = map_devices_to_scan_result(devices)
        assert len(result.clients) == 1
        client = result.clients[0]
        assert client.mac_address == "56:96:B9:6A:D5:6A"
        assert client.associated_bssid == "50:BA:7D:5A:8D:1F"
        assert client.manufacturer == "Apple"
        assert "HomeNetwork" in client.probed_ssids
        assert "CoffeeShop" in client.probed_ssids

    def test_channel_filter(self):
        devices = [{"devmac": "AA:BB:CC:DD:EE:FF", "type": "Wi-Fi AP",
                     "strongest_signal": -50, "first_time": 1000, "last_time": 1000,
                     "device": {**SAMPLE_AP, "kismet.device.base.channel": "6"}}]
        result = map_devices_to_scan_result(devices, channels=[1, 11])
        assert len(result.networks) == 0

    def test_mixed_devices(self):
        devices = [
            {"devmac": "0A:58:28:16:14:7A", "type": "Wi-Fi AP",
             "strongest_signal": -23, "first_time": 1000, "last_time": 1000,
             "device": SAMPLE_AP},
            {"devmac": "56:96:B9:6A:D5:6A", "type": "Wi-Fi Client",
             "strongest_signal": -45, "first_time": 1000, "last_time": 1000,
             "device": SAMPLE_CLIENT},
        ]
        result = map_devices_to_scan_result(devices)
        assert len(result.networks) == 1
        assert len(result.clients) == 1


# ── DB reader ───────────────────────────────────────────────────────────


class TestKismetDbReader:
    def test_read_devices_from_sqlite(self, tmp_path):
        db_path = tmp_path / "test.kismet"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, "
            "phyname TEXT, devmac TEXT, strongest_signal INT, min_lat REAL, "
            "min_lon REAL, max_lat REAL, max_lon REAL, avg_lat REAL, avg_lon REAL, "
            "bytes_data INT, type TEXT, device TEXT)"
        )
        conn.execute(
            "INSERT INTO devices VALUES (1000, 2000, 'key1', 'IEEE802.11', "
            "'AA:BB:CC:DD:EE:FF', -30, 0, 0, 0, 0, 0, 0, 100, 'Wi-Fi AP', ?)",
            (json.dumps(SAMPLE_AP),),
        )
        conn.commit()
        conn.close()

        reader = KismetDbReader(db_path)
        devices = reader.read_devices()
        assert len(devices) == 1
        assert devices[0]["devmac"] == "AA:BB:CC:DD:EE:FF"
        assert devices[0]["type"] == "Wi-Fi AP"
        assert devices[0]["device"]["kismet.device.base.name"] == "QF-1110"


class TestFindKismetDb:
    def test_finds_kismet_file(self, tmp_path):
        db_file = tmp_path / "survey-20260413-1.kismet"
        db_file.write_text("fake")
        assert find_kismet_db(tmp_path) == db_file

    def test_returns_none_when_empty(self, tmp_path):
        assert find_kismet_db(tmp_path) is None
