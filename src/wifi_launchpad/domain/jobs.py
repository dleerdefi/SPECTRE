"""Portable workflow job models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class JobType(Enum):
    """Normalized workflow jobs."""

    DOCTOR = "doctor"
    SURVEY = "survey"
    TARGETS = "targets"
    CAPTURE = "capture"
    VALIDATE = "validate"
    EXPORT = "export"
    CRACK = "crack"
    CASES = "cases"
    REPORT = "report"
    EVIL_PORTAL = "evil_portal"


class JobStatus(Enum):
    """Execution status for a workflow job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass
class JobRecord:
    """Portable record of a workflow action."""

    job_type: JobType
    status: JobStatus
    started_at: datetime
    provider: Optional[str] = None
    finished_at: Optional[datetime] = None
    target: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_type": self.job_type.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "provider": self.provider,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "target": self.target,
            "details": dict(self.details),
            "artifacts": list(self.artifacts),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobRecord":
        finished_at = data.get("finished_at")
        return cls(
            job_type=JobType(data["job_type"]),
            status=JobStatus(data["status"]),
            started_at=datetime.fromisoformat(data["started_at"]),
            provider=data.get("provider"),
            finished_at=datetime.fromisoformat(finished_at) if finished_at else None,
            target=data.get("target"),
            details=dict(data.get("details", {})),
            artifacts=list(data.get("artifacts", [])),
        )


__all__ = ["JobRecord", "JobStatus", "JobType"]

