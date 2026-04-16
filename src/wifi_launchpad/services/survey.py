"""Survey normalization helpers."""

from datetime import datetime
from typing import Iterable, Optional, Sequence

from wifi_launchpad.domain.evidence import EvidenceArtifact, SurveyRecord, SurveySummary
from wifi_launchpad.domain.jobs import JobRecord, JobStatus, JobType
from wifi_launchpad.domain.survey import EncryptionType, ScanResult


def build_survey_record(
    *,
    scan_result: ScanResult,
    provider_name: str,
    duration: int,
    channels: Optional[Iterable[int]] = None,
    case_id: Optional[str] = None,
    extra_artifacts: Optional[Sequence[EvidenceArtifact]] = None,
) -> SurveyRecord:
    """Normalize scan results into the shared survey/evidence model."""

    strongest_network = None
    if scan_result.networks:
        strongest = max(scan_result.networks, key=lambda network: network.signal_strength)
        strongest_network = {
            "ssid": strongest.ssid,
            "bssid": strongest.bssid,
            "signal_strength": strongest.signal_strength,
            "channel": strongest.channel,
            "encryption": strongest.encryption.value,
        }

    summary = SurveySummary(
        network_count=len(scan_result.networks),
        client_count=len(scan_result.clients),
        open_network_count=len(
            [network for network in scan_result.networks if network.encryption == EncryptionType.OPEN]
        ),
        hidden_network_count=len([network for network in scan_result.networks if network.hidden]),
        wps_network_count=len([network for network in scan_result.networks if network.wps_enabled]),
        strongest_network=strongest_network,
    )

    observed_at = scan_result.scan_time or datetime.now()
    artifact_id = f"survey-{observed_at.strftime('%Y%m%d%H%M%S')}"
    artifact = EvidenceArtifact(
        artifact_id=artifact_id,
        kind="survey_snapshot",
        source_tool=provider_name,
        created_at=observed_at,
        metadata={
            "duration": duration,
            "channels": list(channels or scan_result.channels_scanned),
            "network_count": len(scan_result.networks),
            "client_count": len(scan_result.clients),
        },
        validation_status="complete",
    )

    job = JobRecord(
        job_type=JobType.SURVEY,
        status=JobStatus.COMPLETED,
        started_at=observed_at,
        finished_at=datetime.now(),
        provider=provider_name,
        details=summary.to_dict(),
        artifacts=[artifact_id],
    )

    return SurveyRecord(
        provider=provider_name,
        observed_at=observed_at,
        duration=duration,
        channel_plan=list(channels or scan_result.channels_scanned),
        networks=[network.to_dict() for network in scan_result.networks],
        clients=[client.to_dict() for client in scan_result.clients],
        summary=summary,
        artifacts=[artifact, *(extra_artifacts or [])],
        job=job,
        case_id=case_id,
    )
