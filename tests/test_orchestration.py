#!/usr/bin/env python3
"""
Tests for the operator orchestration foundation.
"""

import json
import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from wifi_launchpad.cli import cli
from wifi_launchpad.domain.evidence import EvidenceArtifact
from wifi_launchpad.domain.survey import Client, EncryptionType, Network, ScanResult
from wifi_launchpad.services.doctor import PlatformService
from wifi_launchpad.storage.case_store import CaseStore


class TestPlatformService(unittest.TestCase):
    """Capability detection and recommendation logic."""

    @patch("wifi_launchpad.services.doctor.AdapterManager.discover_adapters", return_value=[])
    @patch("wifi_launchpad.services.doctor.subprocess.run")
    @patch("wifi_launchpad.services.doctor.shutil.which")
    def test_inspect_platform_prefers_best_available_stack(
        self,
        mock_which,
        mock_run,
        _mock_discover_adapters,
    ):
        available = {
            "iw",
            "kismet",
            "bettercap",
            "aircrack-ng",
            "airodump-ng",
            "aireplay-ng",
            "hcxdumptool",
            "hcxpcapngtool",
            "tshark",
            "hashcat",
            "docker",
        }

        mock_which.side_effect = lambda executable: (
            f"/usr/bin/{executable}" if executable in available else None
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["tool", "--version"],
            returncode=0,
            stdout="tool 1.0.0\n",
            stderr="",
        )

        report = PlatformService().inspect_platform()

        self.assertEqual(report.recommended_providers["survey"], "kismet")
        self.assertEqual(report.recommended_providers["active_ops"], "bettercap")
        self.assertEqual(report.recommended_providers["capture"], "hcx-psk-pipeline")
        self.assertEqual(report.recommended_providers["convert"], "hcx-convert")
        self.assertEqual(report.recommended_providers["analysis"], "wireshark-analysis")
        self.assertEqual(report.recommended_providers["crack"], "hashcat")

        providers = {provider.name: provider for provider in report.providers}
        self.assertTrue(providers["kismet"].primary)
        self.assertTrue(providers["native-survey"].available)
        self.assertFalse(providers["enterprise-suite"].available)


class TestCaseStore(unittest.TestCase):
    """Case and provenance persistence."""

    def test_record_survey_persists_job_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir))
            record = store.create_case("Office Survey")

            result = ScanResult(
                networks=[
                    Network(
                        bssid="AA:BB:CC:DD:EE:FF",
                        ssid="OfficeWiFi",
                        channel=6,
                        frequency=2437,
                        signal_strength=-42,
                        encryption=EncryptionType.WPA2,
                        wps_enabled=True,
                    )
                ],
                clients=[
                    Client(
                        mac_address="11:22:33:44:55:66",
                        associated_bssid="AA:BB:CC:DD:EE:FF",
                        signal_strength=-55,
                    )
                ],
            )

            platform = PlatformService()
            survey = platform.build_survey_record(
                scan_result=result,
                provider_name="native-survey",
                duration=30,
                channels=[1, 6, 11],
                case_id=record.case_id,
            )
            stored_survey = store.record_survey(record.case_id, survey)

            self.assertEqual(stored_survey.summary.network_count, 1)
            self.assertTrue(stored_survey.artifacts[0].path.endswith(".json"))
            self.assertTrue(Path(stored_survey.artifacts[0].path).exists())

            loaded = store.load_case(record.case_id)
            self.assertEqual(len(loaded.jobs), 1)
            self.assertEqual(loaded.jobs[0].job_type.value, "survey")
            self.assertEqual(len(loaded.artifacts), 1)
            self.assertEqual(loaded.artifacts[0].kind, "survey_snapshot")

    def test_manual_artifacts_preserve_derivation_and_report_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir)
            store = CaseStore(base_path)
            record = store.create_case("Manual Evidence")

            pcap_path = base_path / "capture.pcapng"
            hash_path = base_path / "capture.22000"
            pcap_path.write_text("pcapng-placeholder", encoding="utf-8")
            hash_path.write_text("22000-placeholder", encoding="utf-8")

            pcap_artifact = EvidenceArtifact(
                artifact_id="capture-1",
                kind="pcapng",
                source_tool="kismet",
                created_at=datetime.now(),
                path=str(pcap_path),
                validation_status="complete",
            )
            derived_artifact = EvidenceArtifact(
                artifact_id="hash-1",
                kind="22000",
                source_tool="hcxpcapngtool",
                created_at=datetime.now(),
                path=str(hash_path),
                derived_from=["capture-1"],
                validation_status="complete",
            )

            store.add_artifact(record.case_id, pcap_artifact)
            store.add_artifact(record.case_id, derived_artifact)

            summary = store.summarize_case(record.case_id)
            report_artifact = store.record_report(record.case_id, summary)
            loaded = store.load_case(record.case_id)

            derived = next(artifact for artifact in loaded.artifacts if artifact.artifact_id == "hash-1")
            self.assertEqual(derived.derived_from, ["capture-1"])
            self.assertTrue(Path(report_artifact.path).exists())
            self.assertEqual(loaded.jobs[-1].job_type.value, "report")


class TestCliCaseCommands(unittest.TestCase):
    """CLI wiring for the new case model."""

    def test_cases_init_and_show_emit_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            mock_settings = type("Settings", (), {"case_dir": Path(tmpdir)})()

            with patch("wifi_launchpad.services.cases.get_settings", return_value=mock_settings):
                create = runner.invoke(cli, ["cases", "init", "Lab Case", "--json"])
                self.assertEqual(create.exit_code, 0, create.output)
                created_payload = json.loads(create.output)
                case_id = created_payload["case_id"]

                show = runner.invoke(cli, ["cases", "show", case_id, "--json"])
                self.assertEqual(show.exit_code, 0, show.output)
                show_payload = json.loads(show.output)

            self.assertEqual(show_payload["case"]["name"], "Lab Case")
            self.assertEqual(show_payload["stats"]["artifact_count"], 0)
