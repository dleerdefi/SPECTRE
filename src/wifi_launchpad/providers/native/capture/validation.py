"""Handshake validation helpers."""

from __future__ import annotations

import logging
from pathlib import Path
import subprocess
from typing import Optional

from .models import HandshakeType, ValidationResult

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import availability depends on local env
    from scapy.all import Dot11, Dot11AssoReq, EAPOL, rdpcap
    from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp

    SCAPY_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    SCAPY_AVAILABLE = False
    logger.warning("Scapy unavailable - using fallback validation: %s", exc)


class HandshakeValidator:
    """Validate WPA/WPA2 captures and export cracking formats."""

    def __init__(self) -> None:
        self.use_scapy = SCAPY_AVAILABLE

    def validate_pcap(self, pcap_file: str) -> ValidationResult:
        if not Path(pcap_file).exists():
            return ValidationResult(False, HandshakeType.INVALID, 0.0, validation_messages=["PCAP file not found"])
        if self.use_scapy:
            return self._validate_with_scapy(pcap_file)
        return self._validate_with_tools(pcap_file)

    def _validate_with_scapy(self, pcap_file: str) -> ValidationResult:
        result = ValidationResult(False, HandshakeType.INVALID, 0.0)
        try:
            packets = rdpcap(pcap_file)
            result.total_packets = len(packets)
            ap_mac = None
            client_macs = set()
            eapol_messages = []
            for packet in packets:
                if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                    result.beacon_packets += 1
                    if not result.ssid:
                        try:
                            result.ssid = packet.info.decode("utf-8")
                        except Exception:
                            pass
                if not packet.haslayer(EAPOL):
                    continue
                result.eapol_packets += 1
                if packet.haslayer(Dot11):
                    dot11 = packet.getlayer(Dot11)
                    if dot11.addr1 and dot11.addr2:
                        if dot11.FCfield & 0x01:
                            ap_mac = dot11.addr1
                            client_macs.add(dot11.addr2)
                        else:
                            ap_mac = dot11.addr2
                            client_macs.add(dot11.addr1)
                msg_num = self._determine_eapol_message(packet)
                if msg_num:
                    eapol_messages.append(msg_num)

            result.ap_mac = ap_mac
            if client_macs:
                result.client_mac = sorted(client_macs)[0]
            result.has_m1 = 1 in eapol_messages
            result.has_m2 = 2 in eapol_messages
            result.has_m3 = 3 in eapol_messages
            result.has_m4 = 4 in eapol_messages
            result.has_pmkid = self._check_pmkid(packets)
            self._finalize_result(result)
        except Exception as exc:
            logger.error("Scapy validation error: %s", exc)
            result.validation_messages.append(f"Validation error: {exc}")
        return result

    def _validate_with_tools(self, pcap_file: str) -> ValidationResult:
        result = ValidationResult(False, HandshakeType.INVALID, 0.0)
        try:
            tshark_result = subprocess.run(
                [
                    "tshark",
                    "-r",
                    pcap_file,
                    "-Y",
                    "eapol",
                    "-T",
                    "fields",
                    "-e",
                    "wlan.sa",
                    "-e",
                    "wlan.da",
                    "-e",
                    "eapol.type",
                    "-e",
                    "eapol.keydes.key_info",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            lines = [line for line in tshark_result.stdout.splitlines() if line]
            result.eapol_packets = len(lines)
            if result.eapol_packets == 0:
                result.validation_messages.append("No EAPOL packets found")
                return result

            aircrack_result = subprocess.run(["aircrack-ng", pcap_file], capture_output=True, text=True, timeout=10)
            if "1 handshake" in aircrack_result.stdout:
                result.is_valid = True
                result.handshake_type = HandshakeType.FULL if result.eapol_packets >= 4 else HandshakeType.PARTIAL
                result.quality_score = 90.0 if result.eapol_packets >= 4 else 60.0
                result.validation_messages.append("Handshake detected by aircrack-ng")
            else:
                result.validation_messages.append("No valid handshake detected")

            if self._check_pmkid_with_tools(pcap_file):
                result.has_pmkid = True
                result.is_valid = True
                result.handshake_type = HandshakeType.PMKID
                result.quality_score = 95.0
                result.validation_messages.append("PMKID detected")
        except subprocess.TimeoutExpired:
            result.validation_messages.append("Validation timeout")
        except Exception as exc:
            logger.error("Tool validation error: %s", exc)
            result.validation_messages.append(f"Validation error: {exc}")
        return result

    def _determine_eapol_message(self, packet) -> Optional[int]:
        """Classify EAPOL 4-way handshake message number from key_info flags."""
        if not packet.haslayer(EAPOL):
            return None
        try:
            eapol = packet[EAPOL]
            # Access raw key_info — field name varies by Scapy version
            key_info = getattr(eapol, "key_info", None)
            if key_info is None:
                raw = bytes(eapol)
                if len(raw) >= 7:
                    key_info = (raw[5] << 8) | raw[6]
                else:
                    return None

            key_ack = bool(key_info & 0x0080)
            key_mic = bool(key_info & 0x0100)
            install = bool(key_info & 0x0040)
            secure = bool(key_info & 0x0200)

            if key_ack and not key_mic:
                return 1  # M1: AP → Client (ANonce)
            if not key_ack and key_mic and not install:
                return 2  # M2: Client → AP (SNonce + MIC)
            if key_ack and key_mic and install:
                return 3  # M3: AP → Client (ANonce + MIC + Install + GTK)
            if not key_ack and key_mic and secure:
                return 4  # M4: Client → AP (MIC + Secure)
        except Exception as exc:
            logger.debug("EAPOL classification error: %s", exc)
        return None

    def _check_pmkid(self, packets) -> bool:
        """Check for PMKID in EAPOL M1 packets (RSN IE in key data)."""
        for packet in packets:
            if not packet.haslayer(EAPOL):
                continue
            try:
                raw = bytes(packet[EAPOL])
                # PMKID is in the key data of M1 — look for RSN PMKID tag (0xdd, OUI 00-0f-ac, type 4)
                pmkid_tag = b"\xdd\x14\x00\x0f\xac\x04"
                if pmkid_tag in raw:
                    return True
            except Exception:
                continue
        return False

    def _check_pmkid_with_tools(self, pcap_file: str) -> bool:
        try:
            result = subprocess.run(
                ["hcxpcapngtool", "-o", "/dev/null", pcap_file],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            return False
        return "PMKID" in result.stdout

    def _finalize_result(self, result: ValidationResult) -> None:
        if result.has_pmkid:
            result.handshake_type = HandshakeType.PMKID
            result.is_valid = True
            result.validation_messages.append("PMKID found - ClientLess attack possible")
        elif result.has_m1 and result.has_m2 and result.has_m3 and result.has_m4:
            result.handshake_type = HandshakeType.FULL
            result.is_valid = True
            result.validation_messages.append("Full 4-way handshake captured")
        elif (result.has_m1 and result.has_m2) or (result.has_m2 and result.has_m3) or (result.has_m3 and result.has_m4):
            result.handshake_type = HandshakeType.PARTIAL
            result.is_valid = True
            result.validation_messages.append("Partial handshake captured (crackable)")
        else:
            result.validation_messages.append("Insufficient EAPOL messages for cracking")
        result.quality_score = self._calculate_quality_score(result)

    def _calculate_quality_score(self, result: ValidationResult) -> float:
        score = 0.0
        if result.handshake_type == HandshakeType.FULL:
            score = 80.0
        elif result.handshake_type == HandshakeType.PMKID:
            score = 95.0
        elif result.handshake_type == HandshakeType.PARTIAL:
            score = 50.0
        if result.eapol_packets > 4:
            score += min(result.eapol_packets * 2, 10)
        if result.ap_mac and result.client_mac:
            score += 5
        if result.ssid:
            score += 5
        return min(score, 100.0)

    def export_for_cracking(self, pcap_file: str, output_file: str, format: str = "hccapx") -> bool:
        try:
            if format == "hccapx":
                subprocess.run(["cap2hccapx", pcap_file, output_file], check=True, capture_output=True)
            elif format == "hc22000":
                subprocess.run(["hcxpcapngtool", "-o", output_file, pcap_file], check=True, capture_output=True)
            elif format == "pmkid":
                subprocess.run(["hcxpcapngtool", "--pmkid", output_file, pcap_file], check=True, capture_output=True)
            else:
                logger.error("Unknown export format: %s", format)
                return False
        except subprocess.CalledProcessError as exc:
            logger.error("Export failed: %s", exc)
            return False
        except FileNotFoundError:
            logger.error("Export tool not found for format %s", format)
            return False
        logger.info("Exported handshake to %s (%s)", output_file, format)
        return True
