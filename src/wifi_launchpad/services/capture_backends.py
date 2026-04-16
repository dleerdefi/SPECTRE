"""Helpers for selecting and running capture backends."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from wifi_launchpad.domain.capture import Handshake
from wifi_launchpad.domain.survey import EncryptionType, Network
from wifi_launchpad.providers.external import HCXCaptureProvider


def resolve_capture_provider(
    provider_preference: str,
    hcx_provider: Optional[HCXCaptureProvider],
    network: Network,
) -> str:
    """Return the capture backend that should handle this target."""

    if provider_preference in {"native", "hcx"}:
        return provider_preference
    if hcx_provider and network.encryption in {EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA_WPA2}:
        return "hcx"
    return "native"


def capture_with_hcx(
    hcx_provider: Optional[HCXCaptureProvider],
    *,
    network: Network,
    timeout: int,
    requested_target: Optional[str],
    auto_selected: bool,
) -> Tuple[bool, Optional[Handshake], Optional[Dict]]:
    """Capture using HCX and normalize the result into CLI/service payloads."""

    if not hcx_provider:
        return False, None, None

    success, handshake, hash_file = hcx_provider.capture_psk(
        target_channel=network.channel,
        capture_timeout=timeout,
        target_bssid=network.bssid,
        target_ssid=network.ssid,
    )
    if not success or not handshake:
        return False, None, None

    handshake_info = {
        "network": network.ssid,
        "bssid": network.bssid,
        "file": handshake.pcap_file,
        "quality": handshake.quality_score,
        "capture_time": handshake.time_to_capture,
        "provider": "hcx",
        "hash_file": hash_file,
        "requested_target": requested_target,
        "auto_selected": auto_selected,
    }
    return True, handshake, handshake_info
