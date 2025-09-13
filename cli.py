#!/usr/bin/env python3
"""
WiFi Launchpad CLI - Main Entry Point

Provides both beginner wizard and advanced command-line interface.
"""

import click
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from quickstart.wizard import FirstSuccessWizard
from quickstart.preflight import PreFlightCheck
from core.adapters import AdapterManager

console = Console()


@click.group(invoke_without_command=True)
@click.option('--advanced', is_flag=True, help='Skip wizard and use advanced mode')
@click.pass_context
def cli(ctx, advanced):
    """
    WiFi Launchpad - Your first handshake in 10 minutes!
    
    By default, launches the interactive wizard for beginners.
    Use --advanced for direct command access.
    """
    if ctx.invoked_subcommand is None:
        if advanced:
            # Show advanced mode menu
            show_advanced_menu()
        else:
            # Launch the wizard
            wizard = FirstSuccessWizard()
            wizard.run()


@cli.command()
def wizard():
    """Launch the First Success Wizard (beginner mode)"""
    wizard = FirstSuccessWizard()
    wizard.run()


@cli.command()
def preflight():
    """Run pre-flight system checks"""
    console.print(Panel(
        "[bold cyan]Pre-Flight Check System[/bold cyan]\n\n"
        "Checking your system for WiFi penetration testing readiness...",
        border_style="cyan"
    ))
    
    checker = PreFlightCheck()
    all_passed = checker.run_all_checks()
    
    console.print(f"\n{checker.get_summary()}")
    
    if checker.adapters:
        console.print("\n")
        checker.show_adapter_details()
    
    if not all_passed and checker.fixes_available:
        checker.apply_fixes()
    
    sys.exit(0 if all_passed else 1)


@cli.command()
def adapters():
    """Detect and display WiFi adapters"""
    console.print("[bold cyan]Detecting WiFi Adapters...[/bold cyan]\n")
    
    manager = AdapterManager()
    found_adapters = manager.discover_adapters()
    
    if not found_adapters:
        console.print("[red]No WiFi adapters found![/red]")
        console.print("\nPlease connect a WiFi adapter and try again.")
        sys.exit(1)
    
    # Display adapter table
    table = Table(title="WiFi Adapters", show_header=True, header_style="bold cyan")
    table.add_column("Interface", style="green")
    table.add_column("Chipset", style="yellow")
    table.add_column("Driver")
    table.add_column("Mode")
    table.add_column("Bands")
    table.add_column("Role", style="magenta")
    
    for adapter in found_adapters:
        table.add_row(
            adapter.interface,
            adapter.chipset or "Unknown",
            adapter.driver or "Unknown",
            adapter.current_mode,
            ", ".join(adapter.frequency_bands),
            adapter.assigned_role or "None"
        )
    
    console.print(table)
    
    # Show optimal configuration
    optimal = manager.get_optimal_setup()
    if optimal["monitor"] and optimal["injection"]:
        console.print("\n[green]✅ Dual-adapter configuration detected![/green]")
        console.print(f"  Monitor: {optimal['monitor'].interface} ({optimal['monitor'].chipset})")
        console.print(f"  Injection: {optimal['injection'].interface} ({optimal['injection'].chipset})")
    elif optimal["monitor"] or optimal["injection"]:
        console.print("\n[yellow]⚠️  Single adapter detected - basic functionality available[/yellow]")
    else:
        console.print("\n[red]❌ No suitable adapters for WiFi testing[/red]")


@cli.command()
@click.option('--interface', '-i', help='Interface to enable monitor mode on')
def monitor(interface):
    """Enable monitor mode on an adapter"""
    manager = AdapterManager()
    manager.discover_adapters()
    
    if interface:
        # Find specific adapter
        adapter = next((a for a in manager.adapters if a.interface == interface), None)
        if not adapter:
            console.print(f"[red]Interface {interface} not found![/red]")
            sys.exit(1)
    else:
        # Use the designated monitor adapter
        adapter = manager.monitor_adapter
        if not adapter:
            console.print("[red]No suitable adapter for monitor mode![/red]")
            sys.exit(1)
    
    console.print(f"[cyan]Enabling monitor mode on {adapter.interface}...[/cyan]")
    
    if manager.enable_monitor_mode(adapter):
        console.print(f"[green]✅ Monitor mode enabled on {adapter.interface}[/green]")
    else:
        console.print(f"[red]❌ Failed to enable monitor mode[/red]")
        sys.exit(1)


@cli.command()
@click.option('--target', '-t', help='Target network SSID')
@click.option('--interface', '-i', help='Interface to use for scanning')
@click.option('--duration', '-d', type=int, default=30, help='Scan duration in seconds')
@click.option('--channels', '-c', help='Comma-separated list of channels')
def scan(target, interface, duration, channels):
    """Scan for WiFi networks"""
    import asyncio
    from services.scanner_service import ScannerService, ScanConfig, ScanMode

    console.print("[bold cyan]Starting network scan...[/bold cyan]\n")

    # Parse channels if provided
    channel_list = None
    if channels:
        channel_list = [int(c.strip()) for c in channels.split(',')]

    # Create scanner service
    service = ScannerService()

    # Configure scan
    config = ScanConfig(
        mode=ScanMode.TARGETED if target else ScanMode.DISCOVERY,
        target_ssid=target,
        channels=channel_list,
        duration=duration
    )

    # Run scan
    async def run_scan():
        if not await service.initialize():
            console.print("[red]Failed to initialize scanner[/red]")
            return

        console.print(f"[green]Scanning for {duration} seconds...[/green]")
        console.print(f"[dim]Press Ctrl+C to stop early[/dim]\n")

        if await service.start_scan(config):
            # Show progress
            with console.status("[cyan]Scanning...[/cyan]"):
                await asyncio.sleep(duration)

            results = await service.stop_scan()

            # Display results in table
            if results.networks:
                table = Table(title=f"Found {len(results.networks)} Networks", show_header=True, header_style="bold cyan")
                table.add_column("SSID", style="yellow")
                table.add_column("BSSID", style="dim")
                table.add_column("Channel")
                table.add_column("Security")
                table.add_column("Signal", style="green")
                table.add_column("WPS")

                for network in sorted(results.networks, key=lambda n: n.signal_strength, reverse=True)[:20]:
                    wps_status = "✓" if network.wps_enabled else ""
                    table.add_row(
                        network.ssid[:25] if len(network.ssid) > 25 else network.ssid,
                        network.bssid,
                        str(network.channel),
                        network.encryption.value,
                        f"{network.signal_strength} dBm",
                        wps_status
                    )

                console.print(table)

                # Show statistics
                console.print(f"\n[cyan]Scan Statistics:[/cyan]")
                console.print(f"  Total Networks: {len(results.networks)}")
                console.print(f"  Total Clients: {len(results.clients)}")
                console.print(f"  Open Networks: {len([n for n in results.networks if n.encryption.value == 'Open'])}")
                console.print(f"  WPS Enabled: {len([n for n in results.networks if n.wps_enabled])}")
            else:
                console.print("[yellow]No networks found[/yellow]")
        else:
            console.print("[red]Failed to start scan[/red]")

    try:
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")


@cli.command()
@click.option('--bssid', '-b', required=True, help='Target BSSID')
@click.option('--channel', '-c', type=int, required=True, help='Channel number')
@click.option('--interface', '-i', help='Interface to use')
@click.option('--timeout', '-t', type=int, default=300, help='Capture timeout in seconds')
@click.option('--deauth', '-d', type=int, default=5, help='Number of deauth bursts')
def capture(bssid, channel, interface, timeout, deauth):
    """Capture WPA/WPA2 handshake"""
    from core.capture import CaptureManager, CaptureConfig, DeauthStrategy
    from core.capture import HandshakeValidator
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    console.print(Panel(
        f"[bold cyan]Handshake Capture[/bold cyan]\n\n"
        f"Target: [yellow]{bssid}[/yellow]\n"
        f"Channel: [yellow]{channel}[/yellow]\n"
        f"Timeout: [yellow]{timeout}s[/yellow]",
        border_style="cyan"
    ))

    # Get interface from adapter manager if not specified
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

    # Configure capture
    config = CaptureConfig(
        target_bssid=bssid,
        target_channel=channel,
        capture_timeout=timeout,
        deauth_count=deauth,
        deauth_interval=10,
        min_quality_score=50.0
    )

    # Start capture
    capture_manager = CaptureManager(interface)

    console.print("\n[cyan]Starting capture...[/cyan]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    # Show progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Capturing handshake...", total=None)

        # Update status callback
        def update_status(status):
            descriptions = {
                "capturing": "Monitoring for handshake...",
                "deauthing": "Sending deauth packets...",
                "validating": "Validating captured data...",
                "success": "[green]Handshake captured![/green]",
                "failed": "[red]Capture failed[/red]",
                "timeout": "[yellow]Capture timeout[/yellow]"
            }
            progress.update(task, description=descriptions.get(status.value, status.value))

        capture_manager.on_status_change = update_status

        # Run capture
        try:
            success, handshake = capture_manager.capture_handshake(config)
        except KeyboardInterrupt:
            console.print("\n[yellow]Capture interrupted by user[/yellow]")
            capture_manager.stop()
            sys.exit(0)

    # Display results
    if success and handshake:
        console.print("\n[bold green]✅ Handshake Captured Successfully![/bold green]\n")

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

        # Validate with advanced validator
        console.print("\n[cyan]Validating handshake...[/cyan]")
        validator = HandshakeValidator()
        validation = validator.validate_pcap(handshake.pcap_file)

        if validation.is_valid:
            console.print(f"[green]✓ Valid {validation.handshake_type.value} handshake[/green]")
            for msg in validation.validation_messages:
                console.print(f"  • {msg}")
        else:
            console.print("[red]✗ Invalid handshake[/red]")
            for msg in validation.validation_messages:
                console.print(f"  • {msg}")
    else:
        console.print("\n[red]❌ Handshake capture failed[/red]")
        console.print("Try increasing timeout or moving closer to the target")


@cli.command()
def sandbox():
    """Launch sandbox mode (mobile hotspot tutorial)"""
    console.print(Panel(
        "[bold cyan]Sandbox Mode[/bold cyan]\n\n"
        "This safe learning environment uses your mobile hotspot\n"
        "as a legal target for your first penetration test.",
        border_style="cyan"
    ))
    
    from rich.prompt import Confirm
    if Confirm.ask("\n[yellow]Ready to start sandbox mode?[/yellow]"):
        wizard = FirstSuccessWizard()
        wizard.setup_mobile_hotspot()
        wizard.start_monitor_mode()
        wizard.scan_for_hotspot()
        wizard.capture_handshake()
        wizard.celebrate_success()


def show_advanced_menu():
    """Display advanced mode menu"""
    console.print(Panel(
        "[bold cyan]WiFi Launchpad - Advanced Mode[/bold cyan]\n\n"
        "Available commands:\n\n"
        "[yellow]System:[/yellow]\n"
        "  preflight    - Run system checks\n"
        "  adapters     - List WiFi adapters\n"
        "  monitor      - Enable monitor mode\n\n"
        "[yellow]Operations:[/yellow]\n"
        "  scan         - Scan for networks\n"
        "  capture      - Capture handshake\n"
        "  crack        - Crack captured handshake\n\n"
        "[yellow]Learning:[/yellow]\n"
        "  wizard       - Launch beginner wizard\n"
        "  sandbox      - Safe mobile hotspot test\n\n"
        "Use 'python cli.py COMMAND --help' for more info",
        border_style="cyan"
    ))


@cli.command()
def version():
    """Show version information"""
    console.print("[bold]WiFi Launchpad[/bold]")
    console.print("Version: 1.0.0")
    console.print("Mission: Your first handshake in 10 minutes!")
    console.print("\nDeveloped for the Kali Linux community")
    console.print("GitHub: https://github.com/dleerdefi/wifi-launchpad")


if __name__ == '__main__':
    # Check if running as root when needed
    if len(sys.argv) > 1 and sys.argv[1] in ['monitor', 'capture', 'scan']:
        if os.geteuid() != 0:
            console.print("[yellow]Note: Some operations may require sudo privileges[/yellow]")
    
    cli()