"""Report helpers built on top of the case store."""

from typing import Dict, Tuple

from wifi_launchpad.domain.evidence import EvidenceArtifact
from wifi_launchpad.storage.case_store import CaseStore


def generate_case_report(store: CaseStore, case_id: str) -> Tuple[Dict[str, object], EvidenceArtifact]:
    """Generate and persist a case summary report."""

    summary = store.summarize_case(case_id)
    artifact = store.record_report(case_id, summary)
    return summary, artifact
