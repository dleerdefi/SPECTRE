"""System and platform inspection commands."""

import sys

import click
from rich.panel import Panel
from rich.table import Table

from wifi_launchpad import __version__
from wifi_launchpad.cli.common import console, emit_json, quiet_console, serialize_adapter
from wifi_launchpad.quickstart.preflight import PreFlightCheck, serialize_preflight
from wifi_launchpad.services.doctor import PlatformService


def register_system_commands(cli):
    """Register system-oriented CLI commands."""

    @cli.command()
    @click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
    def preflight(json_output):
        """Run pre-flight system checks."""

        if not json_output:
            console.print(
                Panel(
                    "[bold cyan]Pre-Flight Check System[/bold cyan]\n\n"
                    "Checking your system for WiFi penetration testing readiness...",
                    border_style="cyan",
                )
            )

        checker = PreFlightCheck()
        if json_output:
            checker.console = quiet_console()
        all_passed = checker.run_all_checks()

        if json_output:
            emit_json(serialize_preflight(checker, all_passed))
        else:
            console.print(f"\n{checker.get_summary()}")
            if checker.adapters:
                console.print("\n")
                checker.show_adapter_details()
            if not all_passed and checker.fixes_available:
                checker.apply_fixes()

        sys.exit(0 if all_passed else 1)

    @cli.command()
    @click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
    def doctor(json_output):
        """Inspect platform capabilities and recommended providers."""

        platform = PlatformService()
        report = platform.inspect_platform()
        payload = report.to_dict()

        if json_output:
            emit_json(payload)
            return

        console.print(
            Panel(
                "[bold cyan]Operator Doctor[/bold cyan]\n\n"
                "Inspecting adapters, external tools, and recommended provider stack.",
                border_style="cyan",
            )
        )
        console.print(report.policy_notice)

        if report.adapters:
            adapter_table = Table(title="Adapters", show_header=True, header_style="bold cyan")
            adapter_table.add_column("Interface", style="green")
            adapter_table.add_column("Chipset", style="yellow")
            adapter_table.add_column("Driver")
            adapter_table.add_column("Mode")
            adapter_table.add_column("Bands")
            adapter_table.add_column("Role", style="magenta")

            for adapter in report.adapters:
                if "error" in adapter:
                    adapter_table.add_row("error", "", "", "", "", adapter["error"])
                    continue
                adapter_table.add_row(
                    adapter["interface"],
                    adapter.get("chipset") or "Unknown",
                    adapter.get("driver") or "Unknown",
                    adapter.get("mode") or "Unknown",
                    ", ".join(adapter.get("bands") or []),
                    adapter.get("role") or "None",
                )

            console.print(adapter_table)

        provider_table = Table(title="Providers", show_header=True, header_style="bold cyan")
        provider_table.add_column("Role", style="green")
        provider_table.add_column("Provider", style="yellow")
        provider_table.add_column("State")
        provider_table.add_column("Automation")
        provider_table.add_column("Tools")

        for provider in report.providers:
            tool_summary = ", ".join(f"{tool.name}:{tool.status.value}" for tool in provider.tools)
            state = "primary" if provider.primary else ("available" if provider.available else "missing")
            provider_table.add_row(
                provider.role.value,
                provider.name,
                state,
                provider.automation_level,
                tool_summary,
            )

        console.print(provider_table)
        if report.recommended_providers:
            console.print("\n[cyan]Recommended stack:[/cyan]")
            for role, provider_name in report.recommended_providers.items():
                console.print(f"  {role}: [yellow]{provider_name}[/yellow]")

    @cli.command()
    @click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
    def adapters(json_output):
        """Detect and display WiFi adapters."""

        from wifi_launchpad.domain import AdapterManager

        manager = AdapterManager()
        found_adapters = manager.discover_adapters()

        if json_output:
            emit_json(
                {
                    "adapters": [serialize_adapter(adapter) for adapter in found_adapters],
                    "optimal": {
                        role: serialize_adapter(adapter) if adapter else None
                        for role, adapter in manager.get_optimal_setup().items()
                    },
                }
            )
            return

        console.print("[bold cyan]Detecting WiFi Adapters...[/bold cyan]\n")
        if not found_adapters:
            console.print("[red]No WiFi adapters found![/red]")
            console.print("\nPlease connect a WiFi adapter and try again.")
            sys.exit(1)

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
                adapter.assigned_role or "None",
            )

        console.print(table)
        optimal = manager.get_optimal_setup()
        if optimal["monitor"] and optimal["injection"]:
            console.print("\n[green]Dual-adapter configuration detected![/green]")
            console.print(f"  Monitor: {optimal['monitor'].interface} ({optimal['monitor'].chipset})")
            console.print(f"  Injection: {optimal['injection'].interface} ({optimal['injection'].chipset})")
        elif optimal["monitor"] or optimal["injection"]:
            console.print("\n[yellow]Single adapter detected - basic functionality available[/yellow]")
        else:
            console.print("\n[red]No suitable adapters for WiFi testing[/red]")

    @cli.command()
    @click.option("--interface", "-i", help="Interface to enable monitor mode on")
    def monitor(interface):
        """Enable monitor mode on an adapter."""

        from wifi_launchpad.domain import AdapterManager

        manager = AdapterManager()
        manager.discover_adapters()
        adapter = next((item for item in manager.adapters if item.interface == interface), None) if interface else manager.monitor_adapter
        if not adapter:
            message = f"Interface {interface} not found!" if interface else "No suitable adapter for monitor mode!"
            console.print(f"[red]{message}[/red]")
            sys.exit(1)

        console.print(f"[cyan]Enabling monitor mode on {adapter.interface}...[/cyan]")
        if manager.enable_monitor_mode(adapter):
            console.print(f"[green]Monitor mode enabled on {adapter.interface}[/green]")
            return

        console.print("[red]Failed to enable monitor mode[/red]")
        sys.exit(1)

    @cli.command()
    def version():
        """Show version information."""

        console.print("[bold]SPECTRE[/bold]")
        console.print(f"Version: {__version__}")
        console.print("Mission: Wireless tactical assessment toolkit.")
        console.print("\nGitHub: https://github.com/dleerdefi/spectre")
