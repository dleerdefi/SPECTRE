"""SPECTRE TUI — Recon & Survey menu."""

import asyncio

from rich.table import Table

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error


def recon_menu():
    while True:
        divider("RECON & SURVEY")
        console.print(
            "  [green][1][/green] Quick scan (30s, all channels)\n"
            "  [green][2][/green] Custom survey\n"
            "  [green][3][/green] Back\n"
        )
        choice = prompt("spectre/recon")

        if choice == "1":
            run_survey(duration=30)
        elif choice == "2":
            _run_custom_survey()
        elif choice == "3":
            return
        else:
            warn("Invalid choice.")


def run_survey(duration: int = 30, provider: str = "auto", channels=None):
    """Run a passive WiFi survey, using dual-band parallel scan when available."""

    # Check for dual-adapter to enable parallel survey
    from wifi_launchpad.providers.native.adapters.manager import AdapterManager
    manager = AdapterManager()
    manager.discover_adapters()
    optimal = manager.get_optimal_setup()
    ap_adapter = optimal.get("ap")

    if ap_adapter and provider in ("auto", "native") and not channels:
        return _run_dual_band_survey(manager, optimal, ap_adapter, duration)

    info(f"Starting {provider} survey for {duration}s...")

    from wifi_launchpad.services.scanner_service import ScannerService
    from wifi_launchpad.services.scanner_config import ScanConfig, ScanMode

    service = ScannerService()
    config = ScanConfig(mode=ScanMode.DISCOVERY, duration=duration, channels=channels)

    async def _scan():
        if not await service.initialize():
            error("Failed to initialize scanner. Check adapter.")
            return None
        if not await service.start_scan(config):
            error("Failed to start scan.")
            return None
        for remaining in range(duration, 0, -1):
            print(f"\r\033[36m[*] Scanning... {remaining}s remaining \033[0m", end="", flush=True)
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
        print()
        return await service.stop_scan()

    try:
        results = asyncio.run(_scan())
    except KeyboardInterrupt:
        warn("Scan interrupted.")
        pause()
        return None

    if not results or not results.networks:
        warn("No networks found.")
        pause()
        return results

    display_scan_results(results)
    pause()
    return results


def _run_dual_band_survey(manager, optimal, ap_adapter, duration):
    """Run parallel 2.4 GHz + 5 GHz surveys, merge results."""
    import time
    from wifi_launchpad.providers.native.scanner import NetworkScanner

    primary = optimal.get("injection")
    if not primary:
        warn("No primary adapter found, falling back to single-band.")
        return run_survey(duration=duration)

    channels_24 = [1, 6, 11]
    channels_5 = [36, 40, 44, 48, 149, 153, 157, 161]

    info(f"Dual-band parallel survey for {duration}s...")
    console.print(
        f"  [dim]{primary.interface} → 2.4 GHz | "
        f"{ap_adapter.interface} → 5 GHz[/dim]"
    )

    manager.enable_monitor_mode(primary)
    manager.enable_monitor_mode(ap_adapter)
    time.sleep(1)

    scanner_24 = NetworkScanner(primary.interface)
    scanner_5 = NetworkScanner(ap_adapter.interface)

    if not scanner_24.start_scan(channels=channels_24, write_interval=2):
        error("Failed to start 2.4 GHz scanner.")
        pause()
        return None
    if not scanner_5.start_scan(channels=channels_5, write_interval=2):
        warn("Failed to start 5 GHz scanner, continuing single-band.")
        time.sleep(duration)
        results = scanner_24.stop_scan()
        display_scan_results(results)
        pause()
        return results

    for remaining in range(duration, 0, -1):
        print(f"\r\033[36m[*] Dual-band scanning... {remaining}s remaining \033[0m", end="", flush=True)
        time.sleep(1)
    print()

    results_24 = scanner_24.stop_scan()
    results_5 = scanner_5.stop_scan()
    results_24.merge(results_5)

    info(f"Merged: {len(results_24.networks)} networks, {len(results_24.clients)} clients")
    display_scan_results(results_24)
    pause()
    return results_24


def _run_custom_survey():
    dur = prompt("Duration in seconds [30]")
    duration = int(dur) if dur.isdigit() else 30
    prov = prompt("Provider (auto/kismet/native) [auto]")
    provider = prov if prov in ("auto", "kismet", "native") else "auto"
    ch = prompt("Channels (comma-separated, or Enter for all)")
    channels = [int(c.strip()) for c in ch.split(",") if c.strip().isdigit()] if ch else None
    run_survey(duration=duration, provider=provider, channels=channels)


def display_scan_results(results):
    """Display scan results in a Rich table."""
    table = Table(title="Discovered Networks", show_lines=True)
    table.add_column("#", width=4)
    table.add_column("SSID", width=22)
    table.add_column("BSSID", width=18)
    table.add_column("Ch", width=4)
    table.add_column("Signal", width=8)
    table.add_column("Encryption", width=12)
    table.add_column("WPS", width=5)
    table.add_column("Clients", width=8)

    for i, net in enumerate(results.networks, 1):
        clients = len(results.get_associated_clients(net.bssid))
        enc_color = "red" if net.encryption.value in ("Open", "WEP") else "green"
        table.add_row(
            str(i), net.ssid or "(hidden)", net.bssid, str(net.channel),
            f"{net.signal_strength} dBm",
            f"[{enc_color}]{net.encryption.value}[/{enc_color}]",
            "[yellow]Yes[/yellow]" if net.wps_enabled else "",
            str(clients) if clients else "",
        )

    console.print(table)
    console.print(
        f"\n  Networks: {len(results.networks)}  |  "
        f"Clients: {len(results.clients)}  |  "
        f"Open: {len([n for n in results.networks if n.encryption.value == 'Open'])}  |  "
        f"WPS: {len([n for n in results.networks if n.wps_enabled])}"
    )
