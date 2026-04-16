"""Automated persistent capture campaign command."""

import signal
import sys
import time

import click
from rich.panel import Panel
from rich.markup import escape as rich_escape

from wifi_launchpad.cli.common import console


def register_autopwn_commands(cli):
    """Register the autopwn campaign command."""

    @cli.command()
    @click.option("--scan-time", "-s", type=int, default=90, help="Survey duration (default: 90s)")
    @click.option("--targets", "-t", help="Targets: number, range, or 'all' (e.g., '1,3,5' or '1-5')")
    @click.option("--crack/--no-crack", default=True, help="Auto-crack captured handshakes")
    @click.option("--interface", "-i", help="Monitor interface override")
    def autopwn(scan_time, targets, crack, interface):
        """Scan, analyze, and attack — fully automated chain.

        90-second survey detects networks + clients, analyzes attack vectors,
        then cycles PMKID → deauth per target until captured or exhausted.
        """

        from wifi_launchpad.cli.commands.autopwn_display import (
            print_attack_vectors, print_campaign_summary, print_client_map,
            print_recon_summary, print_target_table,
        )
        from wifi_launchpad.domain import AdapterManager
        from wifi_launchpad.providers.external.hcx import HCXCaptureProvider
        from wifi_launchpad.providers.native.scanner import NetworkScanner
        from wifi_launchpad.services.attack_chain import AttackChain
        from wifi_launchpad.services.capture_targeting import categorize_targets
        from wifi_launchpad.services.db import DatabaseService
        from wifi_launchpad.services.recon import build_recon_report

        console.print(Panel(
            "[bold cyan]AUTOPWN — Persistent Attack Campaign[/bold cyan]\n\n"
            "Phase 1: Survey (detect networks + clients)\n"
            "Phase 2: Recon analysis (identify attack vectors)\n"
            "Phase 3: Attack chain (PMKID → deauth → crack)\n\n"
            "[dim]Ctrl+C once = skip target | Ctrl+C twice = abort[/dim]",
            border_style="cyan",
        ))

        # ── Adapter setup ────────────────────────────────────────────
        manager = AdapterManager()
        manager.discover_adapters()
        optimal = manager.get_optimal_setup()
        monitor_iface = interface or (optimal["monitor"].interface if optimal.get("monitor") else None)
        injection_iface = optimal["injection"].interface if optimal.get("injection") else monitor_iface

        if not monitor_iface:
            console.print("[red]No monitor-capable adapter found[/red]")
            sys.exit(1)

        console.print(f"[green]Monitor: {monitor_iface} | Injection: {injection_iface}[/green]")

        # ── Phase 1: Survey ──────────────────────────────────────────
        scan_results = _run_survey(manager, optimal, monitor_iface, injection_iface, scan_time)

        if not scan_results or not scan_results.networks:
            console.print("[red]No networks found[/red]")
            return

        # Prepare injection adapter for Phase 3
        if optimal.get("injection") and optimal["injection"].current_mode != "monitor":
            manager.enable_monitor_mode(optimal["injection"])

        # ── Phase 2: Recon ───────────────────────────────────────────
        console.print(f"\n[bold cyan]Phase 2: Recon Analysis[/bold cyan]")
        recon = build_recon_report(scan_results)
        categories = categorize_targets(scan_results)

        db = DatabaseService()
        if db.connect():
            counts = db.save_scan(scan_results)
            console.print(f"[dim]DB: {counts['networks']} networks, {counts['clients']} clients saved[/dim]")

        print_recon_summary(recon, len(categories["crackable"]))

        if not recon.targets:
            console.print("[yellow]No crackable targets[/yellow]")
            db.disconnect()
            return

        console.print()
        print_target_table(recon)
        print_client_map(recon)
        print_attack_vectors(recon)

        # ── Target selection ─────────────────────────────────────────
        attack_targets = [intel.network for intel in recon.targets]
        if targets:
            attack_targets = _parse_selection(targets, attack_targets)
            if not attack_targets:
                console.print("[red]Invalid target selection[/red]")
                db.disconnect()
                return

        recon_lookup = {intel.network.bssid: intel for intel in recon.targets}

        # ── Phase 3: Attack ──────────────────────────────────────────
        hcx = HCXCaptureProvider(injection_iface) if HCXCaptureProvider.is_available() else None
        chain = AttackChain(
            monitor_interface=monitor_iface,
            injection_interface=injection_iface,
            hcx_provider=hcx,
            auto_crack=crack,
            on_status=lambda msg: console.print(msg),
            recon_lookup=recon_lookup,
        )

        abort_count = [0]
        orig = signal.getsignal(signal.SIGINT)

        def _sigint(signum, frame):
            abort_count[0] += 1
            if abort_count[0] == 1:
                console.print("\n[yellow]Skipping target (Ctrl+C again to abort)...[/yellow]")
                chain.request_skip()
            else:
                signal.signal(signal.SIGINT, orig)
                raise KeyboardInterrupt

        signal.signal(signal.SIGINT, _sigint)

        console.print(f"\n[bold cyan]Phase 3: Attack ({len(attack_targets)} targets)[/bold cyan]\n")
        try:
            results = chain.run_campaign(attack_targets, scan_results)
        except KeyboardInterrupt:
            console.print("\n[red]Campaign aborted[/red]")
            results = []
        finally:
            signal.signal(signal.SIGINT, orig)

        if results:
            print_campaign_summary(results)
            if db.connected:
                counts = db.save_campaign(results)
                console.print(f"[dim]DB: {counts['attack_logs']} logs, {counts['handshakes']} handshakes saved[/dim]")

        db.disconnect()
        try:
            if optimal.get("monitor"):
                manager.disable_monitor_mode(optimal["monitor"])
        except Exception:
            pass


def _run_survey(manager, optimal, monitor_iface, injection_iface, scan_time):
    """Phase 1: airodump-ng survey on the injection adapter (RTL8812AU).

    The MT7921U (wlan2mon) cannot see associated client frames — only beacons
    and probes. The RTL8812AU sees everything, so we use it for both survey
    and attack phases sequentially (same approach as wifite2).
    """

    from wifi_launchpad.providers.native.scanner import NetworkScanner

    # Ensure wlan0 is in monitor mode (idempotent — manager handles already-monitor case)
    injection_adapter = optimal.get("injection")
    if injection_adapter:
        console.print(f"[cyan]Setting {injection_iface} to monitor mode...[/cyan]")
        manager.enable_monitor_mode(injection_adapter)
        time.sleep(1)

    console.print(f"\n[bold cyan]Phase 1: airodump-ng survey on {injection_iface} ({scan_time}s)[/bold cyan]")
    scanner = NetworkScanner(injection_iface)
    if not scanner.start_scan(write_interval=2):
        console.print("[red]Failed to start airodump-ng[/red]")
        return None
    time.sleep(scan_time)
    return scanner.stop_scan()


def _parse_selection(selection: str, candidates: list) -> list:
    """Parse target selection — accepts indices (1,3,5-7), 'all', BSSIDs, or SSIDs."""

    selection = selection.strip()
    if selection.lower() == "all":
        return candidates

    # Try BSSID/SSID matching first
    matched = [
        c for c in candidates
        if c.bssid.upper() == selection.upper() or c.ssid.lower() == selection.lower()
    ]
    if matched:
        return matched

    # Fall back to numeric indices
    indices = set()
    for part in selection.lower().split(","):
        part = part.strip()
        if "-" in part and ":" not in part:
            try:
                s, e = part.split("-", 1)
                indices.update(range(int(s), int(e) + 1))
            except ValueError:
                return []
        else:
            try:
                indices.add(int(part))
            except ValueError:
                return []

    return [candidates[i - 1] for i in sorted(indices) if 1 <= i <= len(candidates)]
