"""Capture workflow commands."""

import asyncio
import sys

import click
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from wifi_launchpad.cli.common import console


def register_capture_commands(cli):
    """Register capture-oriented CLI commands."""

    @cli.command()
    @click.option("--bssid", "-b", required=True, help="Target BSSID")
    @click.option("--channel", "-c", type=int, required=True, help="Channel number")
    @click.option("--interface", "-i", help="Interface to use")
    @click.option("--timeout", "-t", type=int, default=None, help="Capture timeout in seconds")
    @click.option("--deauth", "-d", type=int, default=None, help="Number of deauth bursts")
    @click.option("--provider", type=click.Choice(["auto", "native", "hcx"]), default="auto", show_default=True, help="Capture backend to use")
    def capture(bssid, channel, interface, timeout, deauth, provider):
        """Capture WPA/WPA2 handshake."""

        from wifi_launchpad.app.settings import get_settings
        from wifi_launchpad.domain import AdapterManager
        from wifi_launchpad.providers.external import HCXCaptureProvider
        from wifi_launchpad.providers.native.capture import CaptureConfig, CaptureManager, HandshakeValidator

        cfg = get_settings().capture
        timeout = timeout or cfg.timeout
        deauth = deauth or cfg.deauth_count

        console.print(
            Panel(
                f"[bold cyan]Handshake Capture[/bold cyan]\n\n"
                f"Target: [yellow]{bssid}[/yellow]\n"
                f"Channel: [yellow]{channel}[/yellow]\n"
                f"Timeout: [yellow]{timeout}s[/yellow]",
                border_style="cyan",
            )
        )

        if not interface:
            manager = AdapterManager()
            manager.discover_adapters()
            optimal = manager.get_optimal_setup()
            if optimal["monitor"]:
                interface = optimal["monitor"].interface
                console.print(f"[green]Using monitor interface: {interface}[/green]")
            else:
                console.print("[red]No suitable interface found![/red]")
                sys.exit(1)

        resolved_provider = provider
        if resolved_provider == "auto":
            resolved_provider = "hcx" if HCXCaptureProvider.is_available() else "native"
        console.print(f"[cyan]Provider:[/cyan] {resolved_provider}")

        if resolved_provider == "hcx":
            hcx_provider = HCXCaptureProvider(interface)
            success, handshake, hash_file = hcx_provider.capture_psk(
                target_channel=channel,
                capture_timeout=timeout,
                target_bssid=bssid,
            )
            if not success or not handshake:
                console.print("\n[red]HCX capture failed[/red]")
                console.print("Try increasing timeout or verifying the target is active on the requested channel")
                return

            table = Table(show_header=False, box=None)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="yellow")
            table.add_row("Provider", "hcx")
            table.add_row("BSSID", handshake.bssid)
            table.add_row("Capture", handshake.pcap_file)
            table.add_row("22000", hash_file or "not produced")
            table.add_row("Duration", f"{handshake.time_to_capture:.1f}s")
            console.print("\n[bold green]HCX capture completed[/bold green]\n")
            console.print(table)
            return

        config = CaptureConfig(
            target_bssid=bssid,
            target_channel=channel,
            capture_timeout=timeout,
            deauth_count=deauth,
            deauth_interval=10,
            min_quality_score=50.0,
        )
        capture_manager = CaptureManager(interface)
        console.print("\n[cyan]Starting capture...[/cyan]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Capturing handshake...", total=None)

            def update_status(status):
                descriptions = {
                    "capturing": "Monitoring for handshake...",
                    "deauthing": "Sending deauth packets...",
                    "validating": "Validating captured data...",
                    "success": "[green]Handshake captured![/green]",
                    "failed": "[red]Capture failed[/red]",
                    "timeout": "[yellow]Capture timeout[/yellow]",
                }
                progress.update(task, description=descriptions.get(status.value, status.value))

            capture_manager.on_status_change = update_status
            try:
                success, handshake = capture_manager.capture_handshake(config)
            except KeyboardInterrupt:
                console.print("\n[yellow]Capture interrupted by user[/yellow]")
                capture_manager.stop()
                sys.exit(0)

        if not success or not handshake:
            console.print("\n[red]Handshake capture failed[/red]")
            console.print("Try increasing timeout or moving closer to the target")
            return

        console.print("\n[bold green]Handshake Captured Successfully![/bold green]\n")
        table = Table(show_header=False, box=None)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        table.add_row("BSSID", handshake.bssid)
        table.add_row("SSID", handshake.ssid)
        table.add_row("Client", handshake.client_mac)
        table.add_row("Quality Score", f"{handshake.quality_score:.1f}/100")
        table.add_row("EAPOL Packets", str(handshake.eapol_packets))
        table.add_row("Capture Time", f"{handshake.time_to_capture:.1f}s")
        table.add_row("File", handshake.pcap_file)
        table.add_row("File Size", f"{handshake.file_size / 1024:.1f} KB")
        console.print(table)

        console.print("\n[cyan]Validating handshake...[/cyan]")
        validation = HandshakeValidator().validate_pcap(handshake.pcap_file)
        if validation.is_valid:
            console.print(f"[green]Valid {validation.handshake_type.value} handshake[/green]")
            for message in validation.validation_messages:
                console.print(f"  • {message}")

            _offer_crack(handshake.pcap_file)
            return

        console.print("[red]Invalid handshake[/red]")
        for message in validation.validation_messages:
            console.print(f"  • {message}")

    @cli.command()
    @click.option("--scan-time", "-s", type=int, default=30, help="Network scan duration (seconds)")
    @click.option("--capture-timeout", "-t", type=int, default=300, help="Handshake capture timeout (seconds)")
    @click.option("--target-ssid", help="Target specific network by SSID")
    @click.option("--target-bssid", help="Target specific network by BSSID")
    @click.option("--provider", type=click.Choice(["auto", "native", "hcx"]), default="auto", show_default=True, help="Capture backend to use")
    def quickcapture(scan_time, capture_timeout, target_ssid, target_bssid, provider):
        """Quick capture workflow: Scan -> Select -> Capture."""

        from wifi_launchpad.services import CaptureService

        console.print(
            Panel(
                "[bold cyan]Quick Capture Workflow[/bold cyan]\n\n"
                "Automated scan -> target selection -> handshake capture",
                border_style="cyan",
            )
        )
        service = CaptureService(provider_preference=provider)

        async def run_capture():
            console.print("[cyan]Initializing capture service...[/cyan]")
            if not await service.initialize():
                console.print("[red]Failed to initialize capture service[/red]")
                return False

            console.print(f"[green]Monitor: {service.monitor_interface}[/green]")
            console.print(f"[green]Injection: {service.injection_interface}[/green]\n")

            if target_ssid or target_bssid:
                console.print(f"[cyan]Searching for target: {target_ssid or target_bssid}[/cyan]")
                success, handshake = await service.targeted_capture(
                    ssid=target_ssid,
                    bssid=target_bssid,
                    scan_duration=scan_time,
                    capture_timeout=capture_timeout,
                )
            else:
                console.print(f"[cyan]Scanning for {scan_time} seconds...[/cyan]")
                success, handshake = await service.quick_capture(
                    scan_duration=scan_time,
                    capture_timeout=capture_timeout,
                )

            if not success or not handshake:
                console.print("\n[red]Capture failed[/red]")
                console.print("Try moving closer to the target or increasing timeouts")
                return False

            if handshake.get("auto_selected"):
                console.print(
                    f"[yellow]Requested target {handshake['requested_target']} was not found. "
                    f"Using available target {handshake['network']} ({handshake['bssid']}).[/yellow]"
                )

            table = Table(show_header=False, box=None)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="yellow")
            table.add_row("Provider", handshake.get("provider", provider))
            table.add_row("Network", handshake["network"])
            table.add_row("BSSID", handshake["bssid"])
            table.add_row("Quality", f"{handshake['quality']:.1f}/100")
            table.add_row("Time", f"{handshake['capture_time']:.1f} seconds")
            table.add_row("File", handshake["file"])
            if handshake.get("hash_file"):
                table.add_row("22000", handshake["hash_file"])

            console.print("\n[bold green]SUCCESS! Handshake captured![/bold green]\n")
            console.print(table)

            crack_target = handshake.get("hash_file") or handshake["file"]
            _offer_crack(crack_target)
            return True

        try:
            success = asyncio.run(run_capture())
            sys.exit(0 if success else 1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Capture interrupted by user[/yellow]")
            asyncio.run(service.cleanup())
            sys.exit(0)


def _offer_crack(capture_file: str) -> None:
    """Prompt the user to crack a captured hash/handshake immediately."""
    from wifi_launchpad.providers.external.hashcat import HashcatProvider

    if not HashcatProvider.is_available():
        console.print(f"\n[cyan]Crack with:[/cyan] spectre crack --hash-file {capture_file}")
        return

    console.print()
    if not click.confirm("Crack this handshake now?", default=True):
        console.print(f"[dim]Crack later: spectre crack --hash-file {capture_file}[/dim]")
        return

    from wifi_launchpad.services.crack_service import CrackService

    console.print("[cyan]Running hashcat...[/cyan]")
    service = CrackService()
    result = service.crack_hash(capture_file, timeout=300)

    if result.cracked:
        console.print(f"\n[bold green]PASSWORD: {result.password}[/bold green]")
        console.print(f"[dim]Method: {result.method}, Time: {result.crack_time:.1f}s[/dim]")
    else:
        console.print(f"[yellow]Not cracked with default wordlists ({result.method})[/yellow]")
        console.print(f"[dim]Try: spectre crack --hash-file {capture_file} -w /path/to/rockyou.txt[/dim]")
