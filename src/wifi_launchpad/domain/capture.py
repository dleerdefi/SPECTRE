"""Capture domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Handshake:
    """Represents a captured WPA/WPA2 handshake."""

    bssid: str
    ssid: str
    client_mac: str
    pcap_file: str
    file_size: int
    eapol_packets: int = 0
    m1_present: bool = False
    m2_present: bool = False
    m3_present: bool = False
    m4_present: bool = False
    is_complete: bool = False
    quality_score: float = 0.0
    capture_time: datetime = field(default_factory=datetime.now)
    capture_method: str = "deauth"
    deauth_count: int = 0
    time_to_capture: float = 0.0
    cracked: bool = False
    password: Optional[str] = None
    crack_time: Optional[float] = None
    crack_method: Optional[str] = None

    def validate(self) -> bool:
        """Check whether enough EAPOL messages were captured to be useful."""

        valid_combinations = [
            self.m1_present and self.m2_present,
            self.m2_present and self.m3_present,
            self.m3_present and self.m4_present,
        ]
        self.is_complete = any(valid_combinations)

        packet_score = min(self.eapol_packets * 10, 40)
        completeness_score = sum(
            [
                self.m1_present * 15,
                self.m2_present * 15,
                self.m3_present * 15,
                self.m4_present * 15,
            ]
        )
        self.quality_score = min(packet_score + completeness_score, 100)
        return self.is_complete

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "client_mac": self.client_mac,
            "pcap_file": self.pcap_file,
            "file_size": self.file_size,
            "eapol_packets": self.eapol_packets,
            "m1_present": self.m1_present,
            "m2_present": self.m2_present,
            "m3_present": self.m3_present,
            "m4_present": self.m4_present,
            "is_complete": self.is_complete,
            "quality_score": self.quality_score,
            "capture_time": self.capture_time.isoformat(),
            "capture_method": self.capture_method,
            "deauth_count": self.deauth_count,
            "time_to_capture": self.time_to_capture,
            "cracked": self.cracked,
            "password": self.password,
            "crack_time": self.crack_time,
            "crack_method": self.crack_method,
        }


@dataclass
class CrackResult:
    """Result of a cracking attempt."""

    cracked: bool
    password: Optional[str] = None
    hash_file: Optional[str] = None
    wordlist_used: Optional[str] = None
    crack_time: Optional[float] = None
    method: str = "dictionary"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cracked": self.cracked,
            "password": self.password,
            "hash_file": self.hash_file,
            "wordlist_used": self.wordlist_used,
            "crack_time": self.crack_time,
            "method": self.method,
        }


@dataclass
class AttackTargetResult:
    """Result of a persistent attack chain against a single target."""

    network_ssid: str
    network_bssid: str
    captured: bool
    skipped: bool
    skip_reason: Optional[str] = None
    handshake: Optional[Handshake] = None
    hash_file: Optional[str] = None
    techniques_tried: List[str] = field(default_factory=list)
    total_time: float = 0.0
    eapol_packets_seen: int = 0
    crack_result: Optional[CrackResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network_ssid": self.network_ssid,
            "network_bssid": self.network_bssid,
            "captured": self.captured,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "handshake": self.handshake.to_dict() if self.handshake else None,
            "hash_file": self.hash_file,
            "techniques_tried": self.techniques_tried,
            "total_time": self.total_time,
            "eapol_packets_seen": self.eapol_packets_seen,
            "crack_result": self.crack_result.to_dict() if self.crack_result else None,
        }


__all__ = ["AttackTargetResult", "CrackResult", "Handshake"]

