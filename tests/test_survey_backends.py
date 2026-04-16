#!/usr/bin/env python3
"""Tests for survey provider routing and Kismet normalization."""

from datetime import datetime
import unittest
from unittest.mock import AsyncMock, patch

from wifi_launchpad.domain.evidence import EvidenceArtifact, PlatformCapabilityReport, ProviderCapability, ProviderRole
from wifi_launchpad.domain.survey import EncryptionType
from wifi_launchpad.providers.external.tshark_wifi import parse_tshark_table
from wifi_launchpad.services.survey import build_survey_record
from wifi_launchpad.services.survey_backends import execute_survey


def _sample_tshark_output() -> str:
    rows = [
        "1712536114.1\tAA:BB:CC:DD:EE:FF\t\t\tOfficeWiFi\t6\t-42\t100\t1\t1\t4\t2\t\t\t",
        "1712536115.2\tAA:BB:CC:DD:EE:FF\t12:22:33:44:55:66\t12:22:33:44:55:66\t\t6\t-55\t\t\t\t\t\t\t\t",
        "1712536116.3\t\t76:88:99:AA:BB:CC\t76:88:99:AA:BB:CC\tCafeNet\t11\t-60\t\t\t\t\t\t\t\t",
    ]
    return "\n".join(rows)


def _survey_report(kismet_available: bool = True, native_available: bool = True) -> PlatformCapabilityReport:
    return PlatformCapabilityReport(
        generated_at=datetime.now(),
        policy_notice="",
        providers=[
            ProviderCapability(name="kismet", role=ProviderRole.SURVEY, available=kismet_available),
            ProviderCapability(name="native-survey", role=ProviderRole.SURVEY, available=native_available),
        ],
    )


class TestTsharkWiFiParser(unittest.TestCase):
    """Validate tshark-based survey normalization."""

    def test_parse_tshark_table_normalizes_networks_and_clients(self):
        result = parse_tshark_table(_sample_tshark_output(), channels=[6, 11])

        self.assertEqual(len(result.networks), 1)
        self.assertEqual(len(result.clients), 2)
        self.assertEqual(result.channels_scanned, [6, 11])

        network = result.networks[0]
        self.assertEqual(network.ssid, "OfficeWiFi")
        self.assertEqual(network.encryption, EncryptionType.WPA2)
        self.assertEqual(network.cipher, "CCMP")
        self.assertEqual(network.authentication, "PSK")

        associated = next(client for client in result.clients if client.associated_bssid)
        self.assertEqual(associated.mac_address, "12:22:33:44:55:66")

        probing = next(client for client in result.clients if not client.associated_bssid)
        self.assertEqual(probing.probed_ssids, ["CafeNet"])

    def test_build_survey_record_preserves_extra_artifacts_after_snapshot(self):
        result = parse_tshark_table(_sample_tshark_output(), channels=[6])
        artifact = EvidenceArtifact(
            artifact_id="pcapng-1",
            kind="pcapng",
            source_tool="kismet",
            created_at=datetime.now(),
            path="/tmp/capture.pcapng",
            validation_status="complete",
        )

        record = build_survey_record(
            scan_result=result,
            provider_name="kismet",
            duration=10,
            channels=[6],
            extra_artifacts=[artifact],
        )

        self.assertEqual(record.artifacts[0].kind, "survey_snapshot")
        self.assertEqual(record.artifacts[1].kind, "pcapng")


class TestSurveyBackends(unittest.IsolatedAsyncioTestCase):
    """Validate provider routing for passive survey."""

    @patch("wifi_launchpad.services.survey_backends.KismetSurveyProvider")
    async def test_execute_survey_auto_prefers_kismet(self, mock_provider_class):
        mock_provider = mock_provider_class.return_value
        mock_provider.run_survey.return_value = (
            parse_tshark_table(_sample_tshark_output(), channels=[6]),
            [
                EvidenceArtifact(
                    artifact_id="pcapng-1",
                    kind="pcapng",
                    source_tool="kismet",
                    created_at=datetime.now(),
                    path="/tmp/capture.pcapng",
                    validation_status="complete",
                )
            ],
        )

        execution = await execute_survey(
            duration=10,
            channels=[6],
            provider_preference="auto",
            capability_report=_survey_report(),
        )

        self.assertEqual(execution.provider_used, "kismet")
        self.assertEqual(execution.extra_artifacts[0].kind, "pcapng")
        mock_provider.run_survey.assert_called_once_with(duration=10, channels=[6])

    @patch("wifi_launchpad.services.survey_backends.run_native_survey", new_callable=AsyncMock)
    @patch("wifi_launchpad.services.survey_backends.KismetSurveyProvider")
    async def test_execute_survey_auto_falls_back_to_native(self, mock_provider_class, mock_native_survey):
        mock_provider_class.return_value.run_survey.side_effect = RuntimeError("kismet boom")
        mock_native_survey.return_value = parse_tshark_table(_sample_tshark_output(), channels=[6])

        execution = await execute_survey(
            duration=10,
            channels=[6],
            provider_preference="auto",
            capability_report=_survey_report(),
        )

        self.assertEqual(execution.provider_used, "native-survey")
        self.assertIn("Kismet survey failed", execution.notice)
        mock_native_survey.assert_awaited_once_with(duration=10, channels=[6])


if __name__ == "__main__":
    unittest.main()
