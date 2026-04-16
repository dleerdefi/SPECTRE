"""Survey provider routing for the packaged runtime."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from wifi_launchpad.domain.evidence import EvidenceArtifact, PlatformCapabilityReport
from wifi_launchpad.domain.survey import ScanResult
from wifi_launchpad.providers.external import KismetSurveyProvider
from wifi_launchpad.services.scanner_config import ScanConfig, ScanMode
from wifi_launchpad.services.scanner_service import ScannerService


@dataclass
class SurveyExecution:
    """Normalized result from running a survey provider."""

    provider_used: str
    scan_result: ScanResult
    extra_artifacts: List[EvidenceArtifact] = field(default_factory=list)
    notice: Optional[str] = None


def resolve_survey_provider(provider_preference: str, capability_report: PlatformCapabilityReport) -> str:
    """Resolve the survey provider to use for the current command."""

    available = {provider.name: provider.available for provider in capability_report.providers}
    requested = {"native": "native-survey", "kismet": "kismet"}.get(provider_preference, provider_preference)

    if provider_preference == "auto":
        return "kismet" if available.get("kismet") else "native-survey"
    if not available.get(requested):
        raise RuntimeError(f"Requested survey provider is not available: {provider_preference}")
    return requested


async def execute_survey(
    *,
    duration: int,
    channels: Optional[Iterable[int]],
    provider_preference: str,
    capability_report: PlatformCapabilityReport,
) -> SurveyExecution:
    """Run a survey through the preferred provider with a native fallback for auto mode."""

    resolved_provider = resolve_survey_provider(provider_preference, capability_report)
    if resolved_provider == "kismet":
        try:
            provider = KismetSurveyProvider()
            result, artifacts = await asyncio.to_thread(provider.run_survey, duration=duration, channels=channels)
            return SurveyExecution(provider_used="kismet", scan_result=result, extra_artifacts=artifacts)
        except RuntimeError as exc:
            if provider_preference != "auto":
                raise
            native = await run_native_survey(duration=duration, channels=channels)
            return SurveyExecution(
                provider_used="native-survey",
                scan_result=native,
                notice=f"Kismet survey failed, using native fallback: {exc}",
            )

    native = await run_native_survey(duration=duration, channels=channels)
    return SurveyExecution(provider_used="native-survey", scan_result=native)


async def run_native_survey(duration: int, channels: Optional[Iterable[int]]) -> ScanResult:
    """Execute the built-in survey path."""

    service = ScannerService()
    if not await service.initialize():
        raise RuntimeError("Failed to initialize the native survey stack")

    config = ScanConfig(
        mode=ScanMode.DISCOVERY,
        channels=list(channels) if channels else None,
        duration=duration,
    )
    if not await service.start_scan(config):
        raise RuntimeError("Failed to start the native survey scan")

    try:
        await asyncio.sleep(duration)
    finally:
        return await service.stop_scan()


__all__ = ["SurveyExecution", "execute_survey", "resolve_survey_provider", "run_native_survey"]
