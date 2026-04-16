"""Recon intelligence domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from wifi_launchpad.domain.survey import Client, Network


@dataclass
class TargetIntel:
    """Intelligence assessment for a single attack target."""

    network: Network
    clients: List[Client] = field(default_factory=list)
    recommended_technique: str = "pmkid"
    difficulty: str = "LOW"
    best_client: Optional[Client] = None
    attack_vectors: List[str] = field(default_factory=list)
    total_client_packets: int = 0
    priority_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.network.ssid,
            "bssid": self.network.bssid,
            "channel": self.network.channel,
            "signal": self.network.signal_strength,
            "encryption": self.network.encryption.value if hasattr(self.network.encryption, "value") else str(self.network.encryption),
            "client_count": len(self.clients),
            "recommended_technique": self.recommended_technique,
            "difficulty": self.difficulty,
            "best_client_mac": self.best_client.mac_address if self.best_client else None,
            "attack_vectors": self.attack_vectors,
            "total_client_packets": self.total_client_packets,
            "priority_score": self.priority_score,
        }


@dataclass
class ReconReport:
    """Full recon intelligence from a scan."""

    targets: List[TargetIntel] = field(default_factory=list)
    total_networks: int = 0
    total_clients: int = 0
    wpa3_count: int = 0
    open_count: int = 0
    enterprise_count: int = 0
    hidden_count: int = 0
    wps_enabled: List[str] = field(default_factory=list)
    probe_leaks: Dict[str, List[str]] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": [t.to_dict() for t in self.targets],
            "total_networks": self.total_networks,
            "total_clients": self.total_clients,
            "wpa3_count": self.wpa3_count,
            "open_count": self.open_count,
            "enterprise_count": self.enterprise_count,
            "hidden_count": self.hidden_count,
            "wps_enabled": self.wps_enabled,
            "probe_leaks": self.probe_leaks,
            "generated_at": self.generated_at.isoformat(),
        }


__all__ = ["ReconReport", "TargetIntel"]
