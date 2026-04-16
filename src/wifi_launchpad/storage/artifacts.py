"""Artifact construction helpers."""

from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional

from wifi_launchpad.domain.evidence import EvidenceArtifact


def build_artifact(
    *,
    kind: str,
    source_tool: str,
    path: Path,
    artifact_id: Optional[str] = None,
    derived_from: Optional[Iterable[str]] = None,
    validation_status: str = "unknown",
    metadata: Optional[Dict[str, object]] = None,
    created_at: Optional[datetime] = None,
) -> EvidenceArtifact:
    """Build a normalized evidence artifact for manual case attachment."""

    timestamp = created_at or datetime.now()
    resolved_path = path.resolve()
    resolved_id = artifact_id or f"{kind}-{timestamp.strftime('%Y%m%d%H%M%S')}-{resolved_path.stem}"
    artifact_metadata = {"filename": resolved_path.name}
    if metadata:
        artifact_metadata.update(metadata)

    return EvidenceArtifact(
        artifact_id=resolved_id,
        kind=kind,
        source_tool=source_tool,
        created_at=timestamp,
        path=str(resolved_path),
        derived_from=list(derived_from or []),
        validation_status=validation_status,
        metadata=artifact_metadata,
    )
