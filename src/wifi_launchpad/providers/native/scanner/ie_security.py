"""Security-related IE parsing mixins."""

import struct

from .ie_models import SecurityInfo


class SecurityParsingMixin:
    def _parse_rsn(self, data: bytes) -> SecurityInfo:
        """Parse RSN (WPA2) Information Element"""
        if len(data) < 2:
            return None

        security = SecurityInfo()
        offset = 0

        # Version
        security.version = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2

        if offset >= len(data):
            return security

        # Group cipher suite
        if offset + 4 <= len(data):
            security.group_cipher = self._parse_cipher_suite(data[offset:offset+4])
            offset += 4

        if offset >= len(data):
            return security

        # Pairwise cipher suites
        if offset + 2 <= len(data):
            count = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            for i in range(count):
                if offset + 4 <= len(data):
                    cipher = self._parse_cipher_suite(data[offset:offset+4])
                    security.pairwise_ciphers.append(cipher)
                    offset += 4

        if offset >= len(data):
            return security

        # AKM suites
        if offset + 2 <= len(data):
            count = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            for i in range(count):
                if offset + 4 <= len(data):
                    akm = self._parse_akm_suite(data[offset:offset+4])
                    security.akm_suites.append(akm)
                    offset += 4

        if offset >= len(data):
            return security

        # RSN Capabilities
        if offset + 2 <= len(data):
            security.rsn_capabilities = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            # Parse capability bits
            security.pre_auth = bool(security.rsn_capabilities & 0x0001)
            security.no_pairwise = bool(security.rsn_capabilities & 0x0002)
            security.ptksa_replay_counter = (security.rsn_capabilities >> 2) & 0x3
            security.gtksa_replay_counter = (security.rsn_capabilities >> 4) & 0x3
            security.mfp_required = bool(security.rsn_capabilities & 0x0040)
            security.mfp_capable = bool(security.rsn_capabilities & 0x0080)
            security.joint_multi_band_rsna = bool(security.rsn_capabilities & 0x0100)
            security.peerkey_enabled = bool(security.rsn_capabilities & 0x0200)
            security.spp_amsdu_capable = bool(security.rsn_capabilities & 0x0400)
            security.spp_amsdu_required = bool(security.rsn_capabilities & 0x0800)
            security.pbac = bool(security.rsn_capabilities & 0x1000)
            security.extended_key_id = bool(security.rsn_capabilities & 0x2000)

        if offset >= len(data):
            return security

        # PMKID Count and PMKIDs
        if offset + 2 <= len(data):
            security.pmkid_count = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            for i in range(security.pmkid_count):
                if offset + 16 <= len(data):
                    pmkid = data[offset:offset+16]
                    security.pmkids.append(pmkid)
                    offset += 16

        if offset >= len(data):
            return security

        # Group Management Cipher Suite
        if offset + 4 <= len(data):
            security.group_management_cipher = self._parse_cipher_suite(data[offset:offset+4])
            offset += 4

        return security

    def _parse_cipher_suite(self, data: bytes) -> str:
        """Parse cipher suite OUI and type"""
        if len(data) < 4:
            return "Unknown"

        oui = data[0:3]
        suite_type = data[3]

        # Microsoft OUI
        if oui == b'\x00\x50\xf2':
            cipher_map = {
                0: "Use group cipher",
                1: "WEP-40",
                2: "TKIP",
                4: "CCMP",
                5: "WEP-104"
            }
        # IEEE 802.11 OUI
        elif oui == b'\x00\x0f\xac':
            cipher_map = {
                0: "Use group cipher",
                1: "WEP-40",
                2: "TKIP",
                3: "Reserved",
                4: "CCMP-128",
                5: "WEP-104",
                6: "BIP-CMAC-128",
                7: "Group addressed traffic not allowed",
                8: "GCMP-128",
                9: "GCMP-256",
                10: "CCMP-256",
                11: "BIP-GMAC-128",
                12: "BIP-GMAC-256",
                13: "BIP-CMAC-256"
            }
        else:
            return f"Vendor({oui.hex()})-{suite_type}"

        return cipher_map.get(suite_type, f"Unknown-{suite_type}")

    def _parse_akm_suite(self, data: bytes) -> str:
        """Parse AKM (Authentication Key Management) suite"""
        if len(data) < 4:
            return "Unknown"

        oui = data[0:3]
        suite_type = data[3]

        # Microsoft OUI (WPA)
        if oui == b'\x00\x50\xf2':
            akm_map = {
                1: "802.1X",
                2: "PSK"
            }
        # IEEE 802.11 OUI (WPA2/WPA3)
        elif oui == b'\x00\x0f\xac':
            akm_map = {
                1: "802.1X",
                2: "PSK",
                3: "FT-802.1X",
                4: "FT-PSK",
                5: "802.1X-SHA256",
                6: "PSK-SHA256",
                7: "TDLS",
                8: "SAE",  # WPA3
                9: "FT-SAE",  # WPA3
                10: "AP-PEERKEY",
                11: "802.1X-SUITE-B",
                12: "802.1X-SUITE-B-192",
                13: "FT-802.1X-SHA384",
                14: "FILS-SHA256",
                15: "FILS-SHA384",
                16: "FT-FILS-SHA256",
                17: "FT-FILS-SHA384",
                18: "OWE"  # Opportunistic Wireless Encryption
            }
        else:
            return f"Vendor({oui.hex()})-{suite_type}"

        return akm_map.get(suite_type, f"Unknown-{suite_type}")

    def _parse_wpa(self, data: bytes) -> SecurityInfo:
        """Parse WPA (not WPA2) IE - similar to RSN but older format"""
        # Similar to RSN parsing but for WPA
        # Simplified version for now
        security = SecurityInfo()
        security.version = 1  # WPA version 1

        # Parse similar to RSN but with WPA-specific handling
        # (Implementation would be similar to _parse_rsn)

        return security

    def _parse_wps(self, data: bytes) -> str:
        """Parse WPS state from vendor IE"""
        # WPS uses TLV format
        offset = 0
        state = "Unknown"

        while offset < len(data) - 4:
            attr_type = struct.unpack('>H', data[offset:offset+2])[0]
            attr_len = struct.unpack('>H', data[offset+2:offset+4])[0]

            if offset + 4 + attr_len > len(data):
                break

            attr_data = data[offset+4:offset+4+attr_len]

            # WPS State attribute
            if attr_type == 0x1044 and attr_len >= 1:
                state_val = attr_data[0]
                state_map = {
                    0x01: "Unconfigured",
                    0x02: "Configured"
                }
                state = state_map.get(state_val, f"Unknown({state_val})")
                break

            offset += 4 + attr_len

        return state

__all__ = ["SecurityParsingMixin"]
