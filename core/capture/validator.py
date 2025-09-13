#!/usr/bin/env python3
"""
Handshake Validation Module

Validates captured WPA/WPA2 handshakes by analyzing EAPOL packets.
Determines handshake completeness and quality for cracking.
"""

import subprocess
import logging
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.all import rdpcap, EAPOL, Dot11, Dot11AssoReq, Dot11Auth
    from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Scapy not available - using fallback validation")

logger = logging.getLogger(__name__)


class HandshakeType(Enum):
    """Types of handshake captures"""
    FULL = "full"  # All 4 EAPOL messages
    PARTIAL = "partial"  # M1+M2 or M2+M3 or M3+M4
    PMKID = "pmkid"  # PMKID ClientLess attack
    INVALID = "invalid"  # Not enough for cracking


@dataclass
class ValidationResult:
    """Result of handshake validation"""
    is_valid: bool
    handshake_type: HandshakeType
    quality_score: float  # 0-100

    # EAPOL messages present
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False

    # Additional info
    has_pmkid: bool = False
    ap_mac: Optional[str] = None
    client_mac: Optional[str] = None
    ssid: Optional[str] = None

    # Packet counts
    total_packets: int = 0
    eapol_packets: int = 0
    beacon_packets: int = 0

    # Quality factors
    signal_quality: float = 0.0  # Based on signal strength
    timing_quality: float = 0.0  # Based on packet timing
    completeness: float = 0.0  # Based on messages present

    # Messages for user
    validation_messages: List[str] = None

    def __post_init__(self):
        if self.validation_messages is None:
            self.validation_messages = []


class HandshakeValidator:
    """Validates WPA/WPA2 handshakes"""

    def __init__(self):
        self.use_scapy = SCAPY_AVAILABLE

    def validate_pcap(self, pcap_file: str) -> ValidationResult:
        """
        Validate a PCAP file for handshake presence

        Args:
            pcap_file: Path to PCAP file

        Returns:
            Validation result with quality metrics
        """
        if not Path(pcap_file).exists():
            return ValidationResult(
                is_valid=False,
                handshake_type=HandshakeType.INVALID,
                quality_score=0.0,
                validation_messages=["PCAP file not found"]
            )

        # Try Scapy validation first
        if self.use_scapy:
            return self._validate_with_scapy(pcap_file)
        else:
            # Fallback to command-line tools
            return self._validate_with_tools(pcap_file)

    def _validate_with_scapy(self, pcap_file: str) -> ValidationResult:
        """Validate using Scapy packet analysis"""
        result = ValidationResult(
            is_valid=False,
            handshake_type=HandshakeType.INVALID,
            quality_score=0.0
        )

        try:
            # Read packets
            packets = rdpcap(pcap_file)
            result.total_packets = len(packets)

            # Extract network info
            ap_mac = None
            client_macs = set()
            ssid = None
            eapol_messages = []

            for packet in packets:
                # Get SSID from beacon/probe response
                if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                    result.beacon_packets += 1
                    if not ssid:
                        try:
                            ssid = packet.info.decode('utf-8')
                            result.ssid = ssid
                        except:
                            pass

                # Process EAPOL packets
                if packet.haslayer(EAPOL):
                    result.eapol_packets += 1

                    # Get MAC addresses
                    if packet.haslayer(Dot11):
                        dot11 = packet.getlayer(Dot11)
                        if dot11.addr1 and dot11.addr2:
                            # Determine AP and client
                            if dot11.FCfield & 0x01:  # To DS
                                ap_mac = dot11.addr1
                                client_macs.add(dot11.addr2)
                            else:  # From DS
                                ap_mac = dot11.addr2
                                client_macs.add(dot11.addr1)

                    # Analyze EAPOL message type
                    eapol_layer = packet.getlayer(EAPOL)
                    if hasattr(eapol_layer, 'type'):
                        # Determine message number (simplified)
                        # Real implementation would check key info field
                        msg_num = self._determine_eapol_message(packet)
                        if msg_num:
                            eapol_messages.append(msg_num)

            # Set discovered MACs
            result.ap_mac = ap_mac
            if client_macs:
                result.client_mac = list(client_macs)[0]

            # Check which messages we have
            result.has_m1 = 1 in eapol_messages
            result.has_m2 = 2 in eapol_messages
            result.has_m3 = 3 in eapol_messages
            result.has_m4 = 4 in eapol_messages

            # Check for PMKID
            result.has_pmkid = self._check_pmkid(packets)

            # Determine handshake type
            if result.has_pmkid:
                result.handshake_type = HandshakeType.PMKID
                result.is_valid = True
                result.validation_messages.append("PMKID found - ClientLess attack possible")
            elif result.has_m1 and result.has_m2 and result.has_m3 and result.has_m4:
                result.handshake_type = HandshakeType.FULL
                result.is_valid = True
                result.validation_messages.append("Full 4-way handshake captured")
            elif (result.has_m1 and result.has_m2) or \
                 (result.has_m2 and result.has_m3) or \
                 (result.has_m3 and result.has_m4):
                result.handshake_type = HandshakeType.PARTIAL
                result.is_valid = True
                result.validation_messages.append("Partial handshake captured (crackable)")
            else:
                result.validation_messages.append("Insufficient EAPOL messages for cracking")

            # Calculate quality score
            result.quality_score = self._calculate_quality_score(result)

        except Exception as e:
            logger.error(f"Scapy validation error: {e}")
            result.validation_messages.append(f"Validation error: {e}")

        return result

    def _validate_with_tools(self, pcap_file: str) -> ValidationResult:
        """Validate using command-line tools (fallback)"""
        result = ValidationResult(
            is_valid=False,
            handshake_type=HandshakeType.INVALID,
            quality_score=0.0
        )

        try:
            # Use tshark to analyze EAPOL packets
            tshark_result = subprocess.run(
                [
                    "tshark", "-r", pcap_file,
                    "-Y", "eapol",
                    "-T", "fields",
                    "-e", "wlan.sa",
                    "-e", "wlan.da",
                    "-e", "eapol.type",
                    "-e", "eapol.keydes.key_info"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = tshark_result.stdout.strip().split('\n')
            eapol_count = len([l for l in lines if l])

            if eapol_count == 0:
                result.validation_messages.append("No EAPOL packets found")
                return result

            result.eapol_packets = eapol_count

            # Use aircrack-ng to check if handshake is present
            aircrack_result = subprocess.run(
                ["aircrack-ng", pcap_file],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse aircrack output
            if "1 handshake" in aircrack_result.stdout:
                result.is_valid = True
                result.handshake_type = HandshakeType.PARTIAL
                result.validation_messages.append("Handshake detected by aircrack-ng")

                # Estimate quality based on EAPOL count
                if eapol_count >= 4:
                    result.handshake_type = HandshakeType.FULL
                    result.quality_score = 90.0
                elif eapol_count >= 2:
                    result.quality_score = 60.0
                else:
                    result.quality_score = 30.0

            else:
                result.validation_messages.append("No valid handshake detected")

            # Check for PMKID using hcxpcapngtool if available
            if self._check_pmkid_with_tools(pcap_file):
                result.has_pmkid = True
                result.handshake_type = HandshakeType.PMKID
                result.is_valid = True
                result.quality_score = 95.0
                result.validation_messages.append("PMKID detected")

        except subprocess.TimeoutExpired:
            result.validation_messages.append("Validation timeout")
        except Exception as e:
            logger.error(f"Tool validation error: {e}")
            result.validation_messages.append(f"Validation error: {e}")

        return result

    def _determine_eapol_message(self, packet) -> Optional[int]:
        """
        Determine EAPOL message number (M1, M2, M3, M4)
        Simplified implementation - real one would check key info fields
        """
        # This is a simplified heuristic
        # Real implementation would check:
        # - Key MIC
        # - Key ACK
        # - Key Install
        # - Key Descriptor Version

        if not packet.haslayer(EAPOL):
            return None

        # For now, return a placeholder
        # Real implementation would analyze key info field
        return None

    def _check_pmkid(self, packets) -> bool:
        """Check if PMKID is present in packets"""
        # PMKID is in RSN IE of association request
        for packet in packets:
            if packet.haslayer(Dot11AssoReq):
                # Check for PMKID in RSN IE
                # This is simplified - real check would parse RSN IE
                return False
        return False

    def _check_pmkid_with_tools(self, pcap_file: str) -> bool:
        """Check for PMKID using hcxpcapngtool"""
        try:
            # Try hcxpcapngtool if available
            result = subprocess.run(
                ["hcxpcapngtool", "-o", "/dev/null", pcap_file],
                capture_output=True,
                text=True,
                timeout=5
            )
            return "PMKID" in result.stdout
        except:
            return False

    def _calculate_quality_score(self, result: ValidationResult) -> float:
        """Calculate overall quality score"""
        score = 0.0

        # Base score from handshake type
        if result.handshake_type == HandshakeType.FULL:
            score = 80.0
        elif result.handshake_type == HandshakeType.PMKID:
            score = 95.0
        elif result.handshake_type == HandshakeType.PARTIAL:
            score = 50.0

        # Bonus for more EAPOL packets
        if result.eapol_packets > 4:
            score += min(result.eapol_packets * 2, 10)

        # Bonus for having all components
        if result.ap_mac and result.client_mac:
            score += 5

        if result.ssid:
            score += 5

        return min(score, 100.0)

    def export_for_cracking(
        self,
        pcap_file: str,
        output_file: str,
        format: str = "hccapx"
    ) -> bool:
        """
        Export handshake in format suitable for cracking

        Args:
            pcap_file: Input PCAP file
            output_file: Output file path
            format: Output format (hccapx, pmkid, hc22000)

        Returns:
            True if export successful
        """
        try:
            if format == "hccapx":
                # Use cap2hccapx or aircrack-ng
                subprocess.run(
                    ["cap2hccapx", pcap_file, output_file],
                    check=True,
                    capture_output=True
                )
            elif format == "hc22000":
                # Use hcxpcapngtool for new hashcat format
                subprocess.run(
                    ["hcxpcapngtool", "-o", output_file, pcap_file],
                    check=True,
                    capture_output=True
                )
            elif format == "pmkid":
                # Extract PMKID only
                subprocess.run(
                    ["hcxpcapngtool", "--pmkid", output_file, pcap_file],
                    check=True,
                    capture_output=True
                )
            else:
                logger.error(f"Unknown export format: {format}")
                return False

            logger.info(f"Exported handshake to {output_file} ({format})")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Export failed: {e}")
            return False
        except FileNotFoundError:
            logger.error(f"Export tool not found for format {format}")
            return False