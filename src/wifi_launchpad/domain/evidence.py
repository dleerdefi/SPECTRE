"""Evidence, provider, and case models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from wifi_launchpad.domain.jobs import JobRecord


class ToolStatus(Enum):
    """Availability status for an external dependency."""

    AVAILABLE = "available"
    MISSING = "missing"
    ERROR = "error"


class ProviderRole(Enum):
    """High-level provider responsibilities."""

    SURVEY = "survey"
    ACTIVE_OPS = "active_ops"
    CAPTURE = "capture"
    CONVERT = "convert"
    ANALYSIS = "analysis"
    CRACK = "crack"
    ENTERPRISE = "enterprise"
    LAB = "lab"
    SOCIAL_ENGINEERING = "social_engineering"


@dataclass
class ToolCapability:
    """Availability and version metadata for a single executable."""

    name: str
    executable: str
    status: ToolStatus
    path: Optional[str] = None
    version: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "executable": self.executable,
            "status": self.status.value,
            "path": self.path,
            "version": self.version,
            "details": self.details,
        }


@dataclass
class ProviderCapability:
    """Availability of a logical provider made up of one or more tools."""

    name: str
    role: ProviderRole
    available: bool
    primary: bool = False
    automation_level: str = "metadata"
    notes: str = ""
    tools: List[ToolCapability] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role.value,
            "available": self.available,
            "primary": self.primary,
            "automation_level": self.automation_level,
            "notes": self.notes,
            "tools": [tool.to_dict() for tool in self.tools],
        }


@dataclass
class EvidenceArtifact:
    """Normalized evidence artifact with provenance metadata."""

    artifact_id: str
    kind: str
    source_tool: str
    created_at: datetime
    immutable: bool = True
    path: Optional[str] = None
    derived_from: List[str] = field(default_factory=list)
    validation_status: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "source_tool": self.source_tool,
            "created_at": self.created_at.isoformat(),
            "immutable": self.immutable,
            "path": self.path,
            "derived_from": list(self.derived_from),
            "validation_status": self.validation_status,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceArtifact":
        return cls(
            artifact_id=data["artifact_id"],
            kind=data["kind"],
            source_tool=data["source_tool"],
            created_at=datetime.fromisoformat(data["created_at"]),
            immutable=data.get("immutable", True),
            path=data.get("path"),
            derived_from=list(data.get("derived_from", [])),
            validation_status=data.get("validation_status", "unknown"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class SurveySummary:
    """Compact summary of a survey result."""

    network_count: int
    client_count: int
    open_network_count: int
    hidden_network_count: int
    wps_network_count: int
    strongest_network: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network_count": self.network_count,
            "client_count": self.client_count,
            "open_network_count": self.open_network_count,
            "hidden_network_count": self.hidden_network_count,
            "wps_network_count": self.wps_network_count,
            "strongest_network": dict(self.strongest_network) if self.strongest_network else None,
        }


@dataclass
class SurveyRecord:
    """Serializable survey payload for JSON or case storage."""

    provider: str
    observed_at: datetime
    duration: int
    channel_plan: List[int] = field(default_factory=list)
    networks: List[Dict[str, Any]] = field(default_factory=list)
    clients: List[Dict[str, Any]] = field(default_factory=list)
    summary: Optional[SurveySummary] = None
    artifacts: List[EvidenceArtifact] = field(default_factory=list)
    job: Optional[JobRecord] = None
    case_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "observed_at": self.observed_at.isoformat(),
            "duration": self.duration,
            "channel_plan": list(self.channel_plan),
            "networks": list(self.networks),
            "clients": list(self.clients),
            "summary": self.summary.to_dict() if self.summary else None,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "job": self.job.to_dict() if self.job else None,
            "case_id": self.case_id,
        }


@dataclass
class CaseRecord:
    """Stored investigation context with jobs and evidence."""

    case_id: str
    name: str
    created_at: datetime
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    jobs: List[JobRecord] = field(default_factory=list)
    artifacts: List[EvidenceArtifact] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "notes": self.notes,
            "tags": list(self.tags),
            "jobs": [job.to_dict() for job in self.jobs],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaseRecord":
        return cls(
            case_id=data["case_id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            notes=data.get("notes", ""),
            tags=list(data.get("tags", [])),
            jobs=[JobRecord.from_dict(job) for job in data.get("jobs", [])],
            artifacts=[EvidenceArtifact.from_dict(artifact) for artifact in data.get("artifacts", [])],
        )


@dataclass
class PlatformCapabilityReport:
    """Complete capability snapshot for the local operator environment."""

    generated_at: datetime
    policy_notice: str
    adapters: List[Dict[str, Any]] = field(default_factory=list)
    providers: List[ProviderCapability] = field(default_factory=list)
    recommended_providers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "policy_notice": self.policy_notice,
            "adapters": list(self.adapters),
            "providers": [provider.to_dict() for provider in self.providers],
            "recommended_providers": dict(self.recommended_providers),
        }


__all__ = [
    "CaseRecord",
    "EvidenceArtifact",
    "PlatformCapabilityReport",
    "ProviderCapability",
    "ProviderRole",
    "SurveyRecord",
    "SurveySummary",
    "ToolCapability",
    "ToolStatus",
]
