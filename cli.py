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
def scan(target, interface):
    """Scan for WiFi networks"""
    console.print("[cyan]Network scanning not yet implemented[/cyan]")
    console.print("This will scan for networks and display them in a table")


@cli.command()
@click.option('--bssid', '-b', required=True, help='Target BSSID')
@click.option('--channel', '-c', type=int, help='Channel number')
@click.option('--interface', '-i', help='Interface to use')
def capture(bssid, channel, interface):
    """Capture WPA/WPA2 handshake"""
    console.print("[cyan]Handshake capture not yet implemented[/cyan]")
    console.print(f"This will capture handshake from {bssid}")


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