"""High-level 802.11 Information Element parser."""

from typing import Any, Dict, List, Optional

from .ie_capabilities import CapabilityParsingMixin
from .ie_security import SecurityParsingMixin
from .ie_types import IEType


class IEParser(SecurityParsingMixin, CapabilityParsingMixin):

    def __init__(self):
        self.parsed_ies: Dict[int, Any] = {}

    def parse_ie_data(self, ie_data: bytes) -> Dict[str, Any]:
        """
        Parse Information Elements from raw data

        Args:
            ie_data: Raw IE data bytes

        Returns:
            Dictionary of parsed information
        """
        result = {
            "ssid": None,
            "supported_rates": [],
            "extended_rates": [],
            "channel": None,
            "country": None,
            "power_constraint": None,
            "ht_capabilities": None,
            "vht_capabilities": None,
            "security": None,
            "wps": False,
            "wps_state": None,
            "extended_capabilities": None,
            "vendor_specific": [],
            "unknown_ies": []
        }

        offset = 0
        while offset < len(ie_data) - 2:
            ie_id = ie_data[offset]
            ie_len = ie_data[offset + 1]

            if offset + 2 + ie_len > len(ie_data):
                break

            ie_payload = ie_data[offset + 2:offset + 2 + ie_len]

            # Parse based on IE type
            if ie_id == IEType.SSID.value:
                result["ssid"] = ie_payload.decode('utf-8', errors='ignore').strip('\x00')

            elif ie_id == IEType.SUPPORTED_RATES.value:
                result["supported_rates"] = self._parse_rates(ie_payload)

            elif ie_id == IEType.DS_PARAMETER_SET.value:
                if ie_len >= 1:
                    result["channel"] = ie_payload[0]

            elif ie_id == IEType.COUNTRY.value:
                result["country"] = self._parse_country(ie_payload)

            elif ie_id == IEType.POWER_CONSTRAINT.value:
                if ie_len >= 1:
                    result["power_constraint"] = ie_payload[0]

            elif ie_id == IEType.HT_CAPABILITIES.value:
                result["ht_capabilities"] = self._parse_ht_capabilities(ie_payload)

            elif ie_id == IEType.RSN.value:  # WPA2
                result["security"] = self._parse_rsn(ie_payload)

            elif ie_id == IEType.EXTENDED_SUPPORTED_RATES.value:
                result["extended_rates"] = self._parse_rates(ie_payload)

            elif ie_id == IEType.VHT_CAPABILITIES.value:
                result["vht_capabilities"] = self._parse_vht_capabilities(ie_payload)

            elif ie_id == IEType.EXTENDED_CAPABILITIES.value:
                result["extended_capabilities"] = self._parse_extended_capabilities(ie_payload)

            elif ie_id == IEType.VENDOR_SPECIFIC.value:
                vendor_info = self._parse_vendor_specific(ie_payload)
                if vendor_info:
                    result["vendor_specific"].append(vendor_info)

                    # Check for WPS
                    if vendor_info.get("type") == "WPS":
                        result["wps"] = True
                        result["wps_state"] = vendor_info.get("state")

                    # Check for WPA (older than WPA2)
                    elif vendor_info.get("type") == "WPA" and not result["security"]:
                        result["security"] = vendor_info.get("security")

            else:
                # Unknown IE
                result["unknown_ies"].append({
                    "id": ie_id,
                    "length": ie_len,
                    "data": ie_payload.hex()
                })

            offset += 2 + ie_len

        return result

    def _parse_rates(self, data: bytes) -> List[float]:
        """Parse supported rates IE"""
        rates = []
        for byte in data:
            # Bit 7 indicates basic rate
            is_basic = bool(byte & 0x80)
            rate = (byte & 0x7F) * 0.5  # Rate in Mbps
            rates.append(rate)
        return rates

    def _parse_country(self, data: bytes) -> Dict[str, Any]:
        """Parse country IE"""
        if len(data) < 3:
            return None

        return {
            "code": data[0:2].decode('ascii', errors='ignore'),
            "environment": data[2]  # Indoor/outdoor/any
        }

    def _parse_vendor_specific(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Vendor Specific IE"""
        if len(data) < 4:
            return None

        oui = data[0:3]
        oui_type = data[3] if len(data) > 3 else 0
        payload = data[4:] if len(data) > 4 else b''

        result = {
            "oui": oui.hex(),
            "type": oui_type,
            "data": payload.hex()
        }

        # Microsoft OUI
        if oui == b'\x00\x50\xf2':
            if oui_type == 1:  # WPA
                result["type"] = "WPA"
                result["security"] = self._parse_wpa(payload)
            elif oui_type == 2:  # WMM/WME
                result["type"] = "WMM"
            elif oui_type == 4:  # WPS
                result["type"] = "WPS"
                result["state"] = self._parse_wps(payload)

        # Apple OUI
        elif oui == b'\x00\x17\xf2':
            result["vendor"] = "Apple"

        # Broadcom OUI
        elif oui == b'\x00\x10\x18':
            result["vendor"] = "Broadcom"

        return result


__all__ = ["IEParser"]
