"""JSON-backed case storage for operator workflow artifacts."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from wifi_launchpad.domain.evidence import CaseRecord, EvidenceArtifact, SurveyRecord
from wifi_launchpad.domain.jobs import JobRecord, JobStatus, JobType


class CaseStore:
    """Simple JSON-backed case and evidence store."""

    def __init__(self, base_path: Path):
        self.base_path = Path(base_path)

    def create_case(self, name: str, notes: str = "", tags: Optional[Iterable[str]] = None) -> CaseRecord:
        created_at = datetime.now()
        slug = self._slugify(name)
        case_id = f"{created_at.strftime('%Y%m%d-%H%M%S')}-{slug}"

        record = CaseRecord(
            case_id=case_id,
            name=name,
            created_at=created_at,
            notes=notes,
            tags=[tag for tag in (tags or []) if tag],
        )

        case_dir = self._case_dir(case_id)
        (case_dir / "surveys").mkdir(parents=True, exist_ok=True)
        (case_dir / "reports").mkdir(parents=True, exist_ok=True)
        (case_dir / "artifacts").mkdir(parents=True, exist_ok=True)

        self._write_case(record)
        return record

    def list_cases(self) -> List[CaseRecord]:
        if not self.base_path.exists():
            return []

        cases = []
        for case_file in sorted(self.base_path.glob("*/case.json")):
            with case_file.open("r", encoding="utf-8") as handle:
                cases.append(CaseRecord.from_dict(json.load(handle)))

        return cases

    def load_case(self, case_id: str) -> CaseRecord:
        case_file = self._case_dir(case_id) / "case.json"
        if not case_file.exists():
            raise FileNotFoundError(f"Case not found: {case_id}")

        with case_file.open("r", encoding="utf-8") as handle:
            return CaseRecord.from_dict(json.load(handle))

    def add_artifact(self, case_id: str, artifact: EvidenceArtifact) -> CaseRecord:
        record = self.load_case(case_id)
        record.artifacts = [existing for existing in record.artifacts if existing.artifact_id != artifact.artifact_id]
        record.artifacts.append(artifact)
        self._write_case(record)
        return record

    def add_job(self, case_id: str, job: JobRecord) -> CaseRecord:
        record = self.load_case(case_id)
        record.jobs.append(job)
        self._write_case(record)
        return record

    def record_survey(self, case_id: str, survey: SurveyRecord) -> SurveyRecord:
        record = self.load_case(case_id)
        survey_dir = self._case_dir(case_id) / "surveys"
        survey_dir.mkdir(parents=True, exist_ok=True)

        survey_path = survey_dir / f"survey-{survey.observed_at.strftime('%Y%m%d-%H%M%S')}.json"
        if survey.artifacts:
            survey.artifacts[0].path = str(survey_path)

        with survey_path.open("w", encoding="utf-8") as handle:
            json.dump(survey.to_dict(), handle, indent=2)

        for artifact in survey.artifacts:
            record.artifacts = [
                existing for existing in record.artifacts if existing.artifact_id != artifact.artifact_id
            ]
            record.artifacts.append(artifact)

        if survey.job:
            record.jobs.append(survey.job)

        self._write_case(record)
        return survey

    def record_report(self, case_id: str, payload: Dict[str, object]) -> EvidenceArtifact:
        record = self.load_case(case_id)
        generated_at = datetime.now()
        report_dir = self._case_dir(case_id) / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        report_path = report_dir / f"report-{generated_at.strftime('%Y%m%d-%H%M%S')}.json"
        artifact = EvidenceArtifact(
            artifact_id=f"report-{generated_at.strftime('%Y%m%d%H%M%S')}",
            kind="report",
            source_tool="spectre",
            created_at=generated_at,
            path=str(report_path),
            validation_status="complete",
            metadata={"report_type": "case_summary"},
        )

        job = JobRecord(
            job_type=JobType.REPORT,
            status=JobStatus.COMPLETED,
            started_at=generated_at,
            finished_at=generated_at,
            provider="spectre",
            details={"artifact_id": artifact.artifact_id},
            artifacts=[artifact.artifact_id],
        )

        full_payload = {
            "generated_at": generated_at.isoformat(),
            "case_id": case_id,
            "summary": payload,
            "artifact": artifact.to_dict(),
            "job": job.to_dict(),
        }

        with report_path.open("w", encoding="utf-8") as handle:
            json.dump(full_payload, handle, indent=2)

        record.artifacts = [existing for existing in record.artifacts if existing.artifact_id != artifact.artifact_id]
        record.artifacts.append(artifact)
        record.jobs.append(job)
        self._write_case(record)

        return artifact

    def summarize_case(self, case_id: str) -> Dict[str, object]:
        record = self.load_case(case_id)
        artifact_counts: Dict[str, int] = {}
        for artifact in record.artifacts:
            artifact_counts[artifact.kind] = artifact_counts.get(artifact.kind, 0) + 1

        latest_job = record.jobs[-1].to_dict() if record.jobs else None
        return {
            "case": record.to_dict(),
            "stats": {
                "job_count": len(record.jobs),
                "artifact_count": len(record.artifacts),
                "artifact_kinds": artifact_counts,
                "latest_job": latest_job,
            },
        }

    def _write_case(self, record: CaseRecord) -> None:
        case_dir = self._case_dir(record.case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        case_file = case_dir / "case.json"
        with case_file.open("w", encoding="utf-8") as handle:
            json.dump(record.to_dict(), handle, indent=2)

    def _case_dir(self, case_id: str) -> Path:
        return self.base_path / case_id

    def _slugify(self, value: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
        return slug or "case"
