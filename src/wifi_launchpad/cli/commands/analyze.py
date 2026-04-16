"""AI-powered WiFi security analysis command.

This command is **optional** — it requires an OpenAI-compatible LLM backend
(e.g. LM Studio, Ollama, vLLM) reachable at the URL configured in
``LLM_URL``.  When no backend is available the command exits gracefully.

Agentic analysis pattern adapted from METATRON
(https://github.com/sooryathejas/METATRON)
Copyright (c) 2026 sooryathejas — MIT License.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.panel import Panel
from rich.table import Table

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.cli.common import console


def register_analyze_commands(cli):
    """Register AI analysis commands with the CLI root."""

    @cli.command()
    @click.option(
        "--duration", "-d", type=int, default=30,
        help="Survey duration in seconds (ignored with --from-file).",
    )
    @click.option(
        "--from-file", "-f", type=click.Path(exists=True),
        help="Analyze a previously saved scan JSON instead of running a live survey.",
    )
    @click.option(
        "--max-rounds", "-r", type=int, default=None,
        help="Maximum LLM tool-dispatch rounds (default: from settings).",
    )
    @click.option("--json-output", is_flag=True, help="Emit results as JSON.")
    def analyze(duration, from_file, max_rounds, json_output):
        """AI-powered WiFi security analysis (requires LLM backend).

        Runs a passive WiFi survey (or loads saved scan data), then sends
        the results to a local LLM for vulnerability analysis.  The LLM
        can request additional tool runs (survey, capture, crack, nmap)
        across multiple rounds.

        Requires an OpenAI-compatible server at LLM_URL (default:
        http://localhost:1234).  Use LM Studio, Ollama, or vLLM.
        """

        asyncio.run(_analyze_async(duration, from_file, max_rounds, json_output))


def _print_round(round_num: int, response: str) -> None:
    """Display a single LLM round to the console."""
    console.print(f"\n[bold cyan]{'─' * 60}[/bold cyan]")
    console.print(f"[bold cyan][AI Analysis — Round {round_num}][/bold cyan]")
    console.print(f"[bold cyan]{'─' * 60}[/bold cyan]")
    console.print(response)


async def _analyze_async(duration, from_file, max_rounds, json_output):
    settings = get_settings()

    # ── Check LLM availability ───────────────────────────────────────
    from wifi_launchpad.services.llm_service import LLMService

    llm = LLMService(settings.llm)
    if not await llm.check_health():
        console.print(
            Panel(
                "[red]LLM backend not available.[/red]\n\n"
                f"Expected an OpenAI-compatible server at [bold]{settings.llm.url}[/bold].\n"
                "Start LM Studio / Ollama / vLLM, or set [bold]LLM_URL[/bold] env var.\n\n"
                "[dim]The analyze command is optional — all other SPECTRE\n"
                "features work without an LLM backend.[/dim]",
                title="AI Analysis Unavailable",
                border_style="red",
            )
        )
        sys.exit(1)

    model_label = llm.model or "auto-detected"
    if not json_output:
        console.print(
            f"\n[green]LLM connected:[/green] {model_label} "
            f"at {settings.llm.url}"
        )

    # ── Get scan data ────────────────────────────────────────────────
    from wifi_launchpad.domain.survey import ScanResult

    if from_file:
        scan_results = _load_scan_file(from_file)
        if not json_output:
            console.print(
                f"[green]Loaded scan data:[/green] {len(scan_results.networks)} networks, "
                f"{len(scan_results.clients)} clients"
            )
    else:
        scan_results = await _run_live_survey(duration, json_output)
        if not scan_results or not scan_results.networks:
            console.print("[yellow]No networks found. Nothing to analyze.[/yellow]")
            return

    # ── Run analysis ─────────────────────────────────────────────────
    from wifi_launchpad.services.analysis_service import AnalysisService

    service = AnalysisService(llm)
    on_round = None if json_output else _print_round

    if not json_output:
        console.print("\n[bold cyan]Starting AI analysis...[/bold cyan]")

    result = await service.analyze(
        scan_results,
        max_rounds=max_rounds,
        on_round=on_round,
    )

    # ── Display results ──────────────────────────────────────────────
    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    console.print(f"\n[bold green]{'═' * 60}[/bold green]")
    console.print(f"[bold green]  Analysis Complete — {result.rounds} round(s)[/bold green]")
    console.print(f"[bold green]{'═' * 60}[/bold green]")

    if result.vulnerabilities:
        table = Table(title="WiFi Vulnerabilities", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("SSID", width=20)
        table.add_column("BSSID", width=18)
        table.add_column("Vulnerability", width=30)
        table.add_column("Attack Vector", width=30)

        severity_colors = {
            "critical": "red", "high": "yellow",
            "medium": "cyan", "low": "green",
        }
        for v in result.vulnerabilities:
            color = severity_colors.get(v.severity, "white")
            table.add_row(
                f"[{color}]{v.severity.upper()}[/{color}]",
                v.ssid, v.bssid, v.name, v.attack,
            )
        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities identified.[/yellow]")

    risk_colors = {
        "CRITICAL": "red", "HIGH": "yellow",
        "MEDIUM": "cyan", "LOW": "green",
    }
    rc = risk_colors.get(result.risk_level, "white")
    console.print(f"\n[bold]Risk Level:[/bold] [{rc}]{result.risk_level}[/{rc}]")
    if result.summary:
        console.print(f"[bold]Summary:[/bold] {result.summary}")


def _load_scan_file(path: str) -> "ScanResult":
    """Load a ScanResult from a JSON file."""
    from wifi_launchpad.domain.survey import (
        Client, EncryptionType, Network, ScanResult, WiFiBand,
    )

    with open(path) as fh:
        data = json.load(fh)

    networks = []
    for net in data.get("networks", []):
        enc = EncryptionType.UNKNOWN
        for member in EncryptionType:
            if member.value.lower() == (net.get("encryption") or "").lower():
                enc = member
                break

        band = None
        if net.get("band"):
            for member in WiFiBand:
                if member.value == net["band"]:
                    band = member
                    break

        networks.append(Network(
            bssid=net.get("bssid", ""),
            ssid=net.get("ssid", ""),
            channel=net.get("channel", 0),
            frequency=net.get("frequency", 0),
            signal_strength=net.get("signal_strength", 0),
            encryption=enc,
            cipher=net.get("cipher"),
            authentication=net.get("authentication"),
            manufacturer=net.get("manufacturer"),
            hidden=net.get("hidden", False),
            wps_enabled=net.get("wps_enabled", False),
            wps_locked=net.get("wps_locked", False),
            band=band,
        ))

    clients = []
    for cl in data.get("clients", []):
        clients.append(Client(
            mac_address=cl.get("mac_address", ""),
            associated_bssid=cl.get("associated_bssid"),
            manufacturer=cl.get("manufacturer"),
            signal_strength=cl.get("signal_strength", 0),
            probed_ssids=cl.get("probed_ssids", []),
        ))

    return ScanResult(
        networks=networks,
        clients=clients,
        duration=data.get("duration", 0),
    )


async def _run_live_survey(duration: int, quiet: bool) -> "ScanResult":
    """Run a live WiFi survey using ScannerService."""
    from wifi_launchpad.services.scanner_service import ScannerService
    from wifi_launchpad.services.scanner_config import ScanConfig, ScanMode

    service = ScannerService()
    if not await service.initialize():
        console.print("[red]Failed to initialize WiFi scanner. Check adapter.[/red]")
        return None

    config = ScanConfig(mode=ScanMode.DISCOVERY, duration=duration)
    if not await service.start_scan(config):
        console.print("[red]Failed to start scan.[/red]")
        return None

    if not quiet:
        console.print(f"[green]Scanning for {duration} seconds...[/green]")

    try:
        await asyncio.sleep(duration)
    except asyncio.CancelledError:
        pass

    return await service.stop_scan()
