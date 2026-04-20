"""Evil portal domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class PortalStatus(Enum):
    """Lifecycle status of an evil portal session."""

    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    CAPTURING = "capturing"
    STOPPED = "stopped"
    FAILED = "failed"


class PortalMode(Enum):
    """Deployment mode for the evil portal."""

    CAPTIVE = "captive"  # DNS redirect + captive portal page (v1)


@dataclass
class PortalTemplate:
    """Metadata for a captive portal HTML template."""

    template_id: str
    name: str
    category: str
    path: str
    fields: List[str] = field(default_factory=lambda: ["email", "password"])
    brand_colors: List[str] = field(default_factory=list)
    ssid_patterns: List[str] = field(default_factory=list)
    logo_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "category": self.category,
            "path": self.path,
            "fields": self.fields,
            "brand_colors": self.brand_colors,
            "ssid_patterns": self.ssid_patterns,
        }


@dataclass
class PortalConfig:
    """Configuration for an evil portal deployment."""

    target_ssid: str
    target_bssid: str
    target_channel: int
    ap_interface: str
    deauth_interface: Optional[str] = None
    template_id: str = "wifi-default"
    gateway_ip: str = "192.169.254.1"
    dhcp_range_start: str = "192.169.254.50"
    dhcp_range_end: str = "192.169.254.200"
    subnet_mask: str = "255.255.255.0"
    server_port: int = 80
    deauth_continuous: bool = True
    deauth_burst_count: int = 100
    deauth_burst_interval: float = 7.0
    use_mana: bool = False
    validate_psk: bool = True
    whitelist_after_capture: bool = True
    timeout: int = 300
    case_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ssid": self.target_ssid,
            "target_bssid": self.target_bssid,
            "target_channel": self.target_channel,
            "ap_interface": self.ap_interface,
            "deauth_interface": self.deauth_interface,
            "template_id": self.template_id,
            "gateway_ip": self.gateway_ip,
            "dhcp_range_start": self.dhcp_range_start,
            "dhcp_range_end": self.dhcp_range_end,
            "server_port": self.server_port,
            "deauth_continuous": self.deauth_continuous,
            "use_mana": self.use_mana,
            "validate_psk": self.validate_psk,
            "whitelist_after_capture": self.whitelist_after_capture,
            "timeout": self.timeout,
            "case_id": self.case_id,
        }


@dataclass
class CapturedCredential:
    """A single credential submission from a victim."""

    credential_id: str
    session_id: str
    timestamp: datetime
    client_mac: str
    client_ip: str
    user_agent: str
    form_data: Dict[str, str]
    os_detected: Optional[str] = None
    psk_validated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "client_mac": self.client_mac,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "form_data": self.form_data,
            "os_detected": self.os_detected,
            "psk_validated": self.psk_validated,
        }


@dataclass
class PortalSession:
    """A running or completed evil portal session."""

    session_id: str
    config: PortalConfig
    status: PortalStatus = PortalStatus.PENDING
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    connected_clients: int = 0
    credentials: List[CapturedCredential] = field(default_factory=list)
    whitelisted_ips: Set[str] = field(default_factory=set)
    hostapd_pid: Optional[int] = None
    dnsmasq_pid: Optional[int] = None
    server_pid: Optional[int] = None
    deauth_pid: Optional[int] = None
    log_file: Optional[str] = None
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        if self.started_at and self.stopped_at:
            return (self.stopped_at - self.started_at).total_seconds()
        return 0.0

    @property
    def psk_captured(self) -> bool:
        return any(c.psk_validated for c in self.credentials)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "config": self.config.to_dict(),
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "connected_clients": self.connected_clients,
            "credentials_count": len(self.credentials),
            "whitelisted_ips": list(self.whitelisted_ips),
            "duration": self.duration,
            "psk_captured": self.psk_captured,
            "error": self.error,
        }


@dataclass
class EvilPortalResult:
    """Final result of an evil portal attack, parallels AttackTargetResult."""

    network_ssid: str
    network_bssid: str
    success: bool
    session: Optional[PortalSession] = None
    credentials_captured: int = 0
    psk_validated: bool = False
    validated_psk: Optional[str] = None
    total_time: float = 0.0
    technique: str = "evil-portal"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network_ssid": self.network_ssid,
            "network_bssid": self.network_bssid,
            "success": self.success,
            "session": self.session.to_dict() if self.session else None,
            "credentials_captured": self.credentials_captured,
            "psk_validated": self.psk_validated,
            "total_time": self.total_time,
            "technique": self.technique,
        }


__all__ = [
    "CapturedCredential",
    "EvilPortalResult",
    "PortalConfig",
    "PortalMode",
    "PortalSession",
    "PortalStatus",
    "PortalTemplate",
]
