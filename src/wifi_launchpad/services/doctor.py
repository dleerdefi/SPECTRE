"""Platform capability discovery for the packaged runtime."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from wifi_launchpad.domain.evidence import PlatformCapabilityReport, ProviderCapability, ProviderRole, ToolCapability, ToolStatus
from wifi_launchpad.domain.survey import ScanResult
from wifi_launchpad.providers.native.adapters import AdapterManager
from wifi_launchpad.services.survey import build_survey_record


@dataclass(frozen=True)
class ToolProbeSpec:
    """Command metadata for a single external dependency."""

    name: str
    executable: str
    version_commands: Sequence[Sequence[str]]
    notes: str = ""


@dataclass(frozen=True)
class ProviderSpec:
    """Grouping of tools into a logical provider."""

    name: str
    role: ProviderRole
    tool_names: Sequence[str]
    automation_level: str
    notes: str = ""


class PlatformService:
    """Detect external tooling and build operator-facing workflow records."""

    TOOL_SPECS: Sequence[ToolProbeSpec] = (
        ToolProbeSpec("iw", "iw", (("--help",),)),
        ToolProbeSpec("kismet", "kismet", (("--version",), ("--help",))),
        ToolProbeSpec("bettercap", "bettercap", (("-version",), ("--help",))),
        ToolProbeSpec("aircrack-ng", "aircrack-ng", (("--help",),)),
        ToolProbeSpec("airodump-ng", "airodump-ng", (("--help",),)),
        ToolProbeSpec("aireplay-ng", "aireplay-ng", (("--help",),)),
        ToolProbeSpec("hcxdumptool", "hcxdumptool", (("-h",), ("--help",))),
        ToolProbeSpec("hcxpcapngtool", "hcxpcapngtool", (("-h",), ("--help",))),
        ToolProbeSpec("tshark", "tshark", (("-v",), ("--version",)), "Wireshark CLI used for packet inspection and evidence validation."),
        ToolProbeSpec("hashcat", "hashcat", (("--version",), ("-V",))),
        ToolProbeSpec("eaphammer", "eaphammer", (("--help",),)),
        ToolProbeSpec("hostapd-mana", "hostapd-mana", (("--help",),)),
        ToolProbeSpec("berate_ap", "berate_ap", (("--help",),)),
        ToolProbeSpec("docker", "docker", (("--version",),)),
    )

    PROVIDER_SPECS: Sequence[ProviderSpec] = (
        ProviderSpec("kismet", ProviderRole.SURVEY, ("kismet",), "recommended-passive", "Preferred passive telemetry and multi-sensor survey engine when present."),
        ProviderSpec("native-survey", ProviderRole.SURVEY, ("iw", "airodump-ng"), "built-in-passive", "Built-in fallback survey path backed by the repo's existing scanner."),
        ProviderSpec("bettercap", ProviderRole.ACTIVE_OPS, ("bettercap",), "external-detected", "Detected for operator workflows but not automatically driven by this repo."),
        ProviderSpec("hcx-psk-pipeline", ProviderRole.CAPTURE, ("hcxdumptool",), "external-detected", "Preferred PSK capture pipeline when the external toolchain is installed."),
        ProviderSpec("aircrack-ng", ProviderRole.CAPTURE, ("aircrack-ng", "airodump-ng", "aireplay-ng"), "compatibility-detected", "Compatibility and fallback capture toolchain."),
        ProviderSpec("hcx-convert", ProviderRole.CONVERT, ("hcxpcapngtool",), "external-detected", "Preferred conversion path for pcapng to 22000 workflows."),
        ProviderSpec("wireshark-analysis", ProviderRole.ANALYSIS, ("tshark",), "analysis-validation", "Preferred packet inspection and evidence-validation toolchain."),
        ProviderSpec("hashcat", ProviderRole.CRACK, ("hashcat",), "external-detected", "Preferred cracking engine when locally installed."),
        ProviderSpec("enterprise-suite", ProviderRole.ENTERPRISE, ("eaphammer", "hostapd-mana", "berate_ap"), "advanced-detected", "Advanced enterprise tooling detected but intentionally left as manual/external workflows."),
        ProviderSpec("wifi-challenge-lab", ProviderRole.LAB, ("docker",), "lab-ready", "Local container runtime suitable for replay and challenge lab scenarios."),
    )

    PRIMARY_PROVIDER_ORDER: Dict[ProviderRole, Sequence[str]] = {
        ProviderRole.SURVEY: ("kismet", "native-survey"),
        ProviderRole.ACTIVE_OPS: ("bettercap",),
        ProviderRole.CAPTURE: ("hcx-psk-pipeline", "aircrack-ng"),
        ProviderRole.CONVERT: ("hcx-convert",),
        ProviderRole.ANALYSIS: ("wireshark-analysis",),
        ProviderRole.CRACK: ("hashcat",),
        ProviderRole.ENTERPRISE: ("enterprise-suite",),
        ProviderRole.LAB: ("wifi-challenge-lab",),
    }

    POLICY_NOTICE = (
        "This repo now models operator-grade workflows, evidence, and capability "
        "discovery. It intentionally automates passive survey, case management, "
        "and provenance tracking while leaving higher-risk external tool execution "
        "as explicit operator-managed workflows."
    )

    def inspect_platform(self) -> PlatformCapabilityReport:
        """Return a normalized local capability report."""

        tools = {spec.name: self._inspect_tool(spec) for spec in self.TOOL_SPECS}
        providers = self._build_providers(tools)
        self._mark_primary_providers(providers)

        return PlatformCapabilityReport(
            generated_at=datetime.now(),
            policy_notice=self.POLICY_NOTICE,
            adapters=self._inspect_adapters(),
            providers=providers,
            recommended_providers=self._recommended_provider_map(providers),
        )

    def build_survey_record(
        self,
        scan_result: ScanResult,
        provider_name: str,
        duration: int,
        channels=None,
        case_id=None,
        extra_artifacts=None,
    ):
        """Delegate survey normalization into the shared builder."""

        return build_survey_record(
            scan_result=scan_result,
            provider_name=provider_name,
            duration=duration,
            channels=channels,
            case_id=case_id,
            extra_artifacts=extra_artifacts,
        )

    def _inspect_tool(self, spec: ToolProbeSpec) -> ToolCapability:
        path = shutil.which(spec.executable)
        if not path:
            return ToolCapability(
                name=spec.name,
                executable=spec.executable,
                status=ToolStatus.MISSING,
                details=spec.notes or f"{spec.executable} not found in PATH",
            )

        version = self._probe_version(spec.executable, spec.version_commands)
        return ToolCapability(
            name=spec.name,
            executable=spec.executable,
            status=ToolStatus.AVAILABLE,
            path=path,
            version=version,
            details=spec.notes or None,
        )

    def _probe_version(self, executable: str, commands: Sequence[Sequence[str]]) -> Optional[str]:
        for args in commands:
            try:
                result = subprocess.run([executable, *args], capture_output=True, text=True, timeout=5)
            except (subprocess.SubprocessError, OSError):
                continue

            output = "\n".join(line for line in (result.stdout.strip(), result.stderr.strip()) if line).strip()
            if output:
                return output.splitlines()[0][:160]

        return None

    def _inspect_adapters(self) -> List[Dict[str, object]]:
        manager = AdapterManager()
        try:
            adapters = manager.discover_adapters()
        except Exception as exc:  # pragma: no cover
            return [{"error": str(exc)}]

        return [
            {
                "interface": adapter.interface,
                "chipset": adapter.chipset,
                "driver": adapter.driver,
                "mode": adapter.current_mode,
                "bands": list(adapter.frequency_bands),
                "monitor_mode": adapter.monitor_mode,
                "packet_injection": adapter.packet_injection,
                "role": adapter.assigned_role,
            }
            for adapter in adapters
        ]

    def _build_providers(self, tools: Dict[str, ToolCapability]) -> List[ProviderCapability]:
        providers = []
        for spec in self.PROVIDER_SPECS:
            provider_tools = [tools[name] for name in spec.tool_names]
            providers.append(
                ProviderCapability(
                    name=spec.name,
                    role=spec.role,
                    available=all(tool.status == ToolStatus.AVAILABLE for tool in provider_tools),
                    automation_level=spec.automation_level,
                    notes=spec.notes,
                    tools=provider_tools,
                )
            )

        return providers

    def _mark_primary_providers(self, providers: List[ProviderCapability]) -> None:
        by_role: Dict[ProviderRole, List[ProviderCapability]] = {}
        for provider in providers:
            by_role.setdefault(provider.role, []).append(provider)

        for role, preferred_names in self.PRIMARY_PROVIDER_ORDER.items():
            candidates = {provider.name: provider for provider in by_role.get(role, [])}
            for name in preferred_names:
                provider = candidates.get(name)
                if provider and provider.available:
                    provider.primary = True
                    break

    def _recommended_provider_map(self, providers: List[ProviderCapability]) -> Dict[str, str]:
        return {provider.role.value: provider.name for provider in providers if provider.primary}
