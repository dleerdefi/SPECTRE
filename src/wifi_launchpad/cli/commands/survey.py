"""Survey and scanning commands."""

import asyncio
import sys

import click
from rich.panel import Panel
from rich.table import Table

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.cli.common import console, emit_json
from wifi_launchpad.services.doctor import PlatformService
from wifi_launchpad.services.survey_backends import execute_survey
from wifi_launchpad.storage.case_store import CaseStore


def register_survey_commands(cli):
    """Register scanning and passive survey commands."""

    @cli.command()
    @click.option("--target", "-t", help="Target network SSID")
    @click.option("--interface", "-i", help="Interface to use for scanning")
    @click.option("--duration", "-d", type=int, default=30, help="Scan duration in seconds")
    @click.option("--channels", "-c", help="Comma-separated list of channels")
    def scan(target, interface, duration, channels):
        """Scan for WiFi networks."""

        from wifi_launchpad.services import ScanConfig, ScanMode, ScannerService

        del interface  # Kept for compatibility until interface selection is refactored.
        console.print("[bold cyan]Starting network scan...[/bold cyan]\n")
        channel_list = [int(channel.strip()) for channel in channels.split(",")] if channels else None
        service = ScannerService()
        config = ScanConfig(
            mode=ScanMode.TARGETED if target else ScanMode.DISCOVERY,
            target_ssid=target,
            channels=channel_list,
            duration=duration,
        )

        async def run_scan():
            if not await service.initialize():
                console.print("[red]Failed to initialize scanner[/red]")
                return

            console.print(f"[green]Scanning for {duration} seconds...[/green]")
            console.print("[dim]Press Ctrl+C to stop early[/dim]\n")

            if not await service.start_scan(config):
                console.print("[red]Failed to start scan[/red]")
                return

            try:
                await asyncio.sleep(duration)
            except asyncio.CancelledError:
                pass

            results = await service.stop_scan()
            if not results.networks:
                console.print("[yellow]No networks found[/yellow]")
                return

            table = Table(title=f"Found {len(results.networks)} Networks", show_header=True, header_style="bold cyan")
            table.add_column("SSID", style="yellow")
            table.add_column("BSSID", style="dim")
            table.add_column("Vendor", style="magenta")
            table.add_column("Ch")
            table.add_column("Security")
            table.add_column("Signal", style="green")
            table.add_column("WPS")
            table.add_column("Clients")

            for network in sorted(results.networks, key=lambda item: item.signal_strength, reverse=True)[:20]:
                client_count = len([client for client in results.clients if client.associated_bssid == network.bssid])
                table.add_row(
                    network.ssid[:20] if len(network.ssid) > 20 else network.ssid,
                    network.bssid,
                    network.manufacturer[:12] if network.manufacturer else "Unknown",
                    str(network.channel),
                    network.encryption.value,
                    f"{network.signal_strength} dBm",
                    "✓" if network.wps_enabled else "",
                    str(client_count) if client_count > 0 else "",
                )

            console.print(table)
            console.print(f"\n[cyan]Scan Statistics:[/cyan]")
            console.print(f"  Total Networks: {len(results.networks)}")
            console.print(f"  Total Clients: {len(results.clients)}")
            console.print(f"  Open Networks: {len([item for item in results.networks if item.encryption.value == 'Open'])}")
            console.print(f"  WPS Enabled: {len([item for item in results.networks if item.wps_enabled])}")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_scan())
            finally:
                if service.scanner:
                    loop.run_until_complete(service.stop_scan())
                loop.close()
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            if service.scanner:
                asyncio.run(service.stop_scan())

    @cli.command()
    @click.option("--duration", "-d", type=int, default=30, help="Survey duration in seconds")
    @click.option("--channels", "-c", help="Comma-separated list of channels")
    @click.option("--provider", type=click.Choice(["auto", "native", "kismet"]), default="auto", show_default=True, help="Survey provider to use")
    @click.option("--case-id", help="Attach the survey to an existing case")
    @click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
    def survey(duration, channels, provider, case_id, json_output):
        """Run a passive survey and normalize the result into case/evidence data."""

        channel_list = [int(channel.strip()) for channel in channels.split(",") if channel.strip()] if channels else None
        platform = PlatformService()
        capability_report = platform.inspect_platform()
        recommended_provider = capability_report.recommended_providers.get("survey")

        if not json_output:
            console.print(
                Panel(
                    "[bold cyan]Passive Survey[/bold cyan]\n\n"
                    "Running a normalized passive survey and packaging the result as evidence.",
                    border_style="cyan",
                )
            )

        try:
            execution = asyncio.run(
                execute_survey(
                    duration=duration,
                    channels=channel_list,
                    provider_preference=provider,
                    capability_report=capability_report,
                )
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]Survey interrupted by user[/yellow]")
            sys.exit(1)
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc

        results = execution.scan_result
        provider_used = execution.provider_used

        survey_record = platform.build_survey_record(
            scan_result=results,
            provider_name=provider_used,
            duration=duration,
            channels=channel_list,
            case_id=case_id,
            extra_artifacts=execution.extra_artifacts,
        )

        if case_id:
            store = CaseStore(get_settings().case_dir)
            try:
                survey_record = store.record_survey(case_id, survey_record)
            except FileNotFoundError as exc:
                raise click.ClickException(str(exc)) from exc

        payload = survey_record.to_dict()
        payload["recommended_provider"] = recommended_provider
        payload["provider_requested"] = provider
        payload["provider_used"] = provider_used

        if json_output:
            emit_json(payload)
            return

        if execution.notice:
            console.print(f"[yellow]{execution.notice}[/yellow]")
        elif recommended_provider and recommended_provider != provider_used:
            console.print(
                f"[yellow]Doctor recommends {recommended_provider} as the primary survey provider; "
                f"this command used {provider_used} instead.[/yellow]"
            )

        summary = survey_record.summary.to_dict() if survey_record.summary else {}
        console.print(
            f"[green]Survey complete:[/green] {summary.get('network_count', 0)} networks, "
            f"{summary.get('client_count', 0)} clients"
        )

        if survey_record.networks:
            table = Table(title="Survey Results", show_header=True, header_style="bold cyan")
            table.add_column("SSID", style="yellow")
            table.add_column("BSSID", style="dim")
            table.add_column("Ch")
            table.add_column("Security")
            table.add_column("Signal", style="green")
            table.add_column("Clients")

            associated_by_bssid = {}
            for client in survey_record.clients:
                bssid = client.get("associated_bssid")
                if bssid:
                    associated_by_bssid[bssid] = associated_by_bssid.get(bssid, 0) + 1

            networks = sorted(survey_record.networks, key=lambda item: item.get("signal_strength", -1000), reverse=True)
            for network in networks[:20]:
                table.add_row(
                    network.get("ssid") or "<hidden>",
                    network.get("bssid", ""),
                    str(network.get("channel", "")),
                    network.get("encryption", "Unknown"),
                    f"{network.get('signal_strength', '?')} dBm",
                    str(associated_by_bssid.get(network.get("bssid"), 0)),
                )

            console.print(table)
        else:
            console.print("[yellow]No networks found during the survey window[/yellow]")

        if case_id and survey_record.artifacts:
            console.print(f"[cyan]Stored in case {case_id}: {survey_record.artifacts[0].path}[/cyan]")
