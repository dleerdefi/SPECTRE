"""SPECTRE TUI — AI Analysis menu."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from pathlib import Path

from rich.table import Table

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error, success
from wifi_launchpad.cli.tui.recon import display_scan_results

_settings = {
    "auto_attack": False,
    "max_rounds": None,
    "auto_export": False,
    "last_result": None,
}


def analysis_menu():
    from wifi_launchpad.app.settings import get_settings
    from wifi_launchpad.services.llm_service import LLMService

    settings = get_settings()
    llm = LLMService(settings.llm)

    info("Checking LLM backend...")
    healthy = asyncio.run(llm.check_health())

    if not healthy:
        error(f"LLM not available at {settings.llm.url}")
        console.print(
            "[dim]  Start LM Studio / Ollama / vLLM, or set LLM_URL env var.\n"
            "  The analyze feature is optional — all other SPECTRE features work without it.[/dim]"
        )
        pause()
        return

    success(f"LLM connected: {llm.model}")

    while True:
        divider("AI ANALYSIS")
        aa = "[green]ON[/green]" if _settings["auto_attack"] else "[red]OFF[/red]"
        console.print(
            f"  [green][1][/green] Analyze live survey\n"
            f"  [green][2][/green] Analyze from file\n"
            f"  [green][3][/green] Settings  [dim](auto-attack: {aa})[/dim]\n"
            f"  [green][4][/green] Export last analysis for review\n"
            f"  [green][5][/green] Import corrections\n"
            f"  [green][6][/green] Back\n"
        )
        choice = prompt("spectre/analyze")

        if choice == "1":
            _run_live(llm)
        elif choice == "2":
            _run_file(llm)
        elif choice == "3":
            _settings_menu()
        elif choice == "4":
            _export_last()
        elif choice == "5":
            _import_corrections()
        elif choice == "6":
            return
        else:
            warn("Invalid choice.")


def _run_live(llm):
    dur = prompt("Survey duration in seconds [30]")
    duration = int(dur) if dur.isdigit() else 30
    info(f"Running {duration}s survey then AI analysis...")

    from wifi_launchpad.services.analysis_service import AnalysisService

    service = AnalysisService(llm)

    async def _go():
        from wifi_launchpad.services.scanner_service import ScannerService
        from wifi_launchpad.services.scanner_config import ScanConfig, ScanMode

        scanner = ScannerService()
        if not await scanner.initialize():
            error("Failed to initialize scanner.")
            return None
        config = ScanConfig(mode=ScanMode.DISCOVERY, duration=duration)
        if not await scanner.start_scan(config):
            error("Failed to start scan.")
            return None
        for remaining in range(duration, 0, -1):
            print(f"\r\033[36m[*] Scanning... {remaining}s remaining \033[0m", end="", flush=True)
            await asyncio.sleep(1)
        print()
        scan_results = await scanner.stop_scan()

        if not scan_results or not scan_results.networks:
            warn("No networks found.")
            return None

        display_scan_results(scan_results)
        info("Starting AI analysis...")
        return await service.analyze(
            scan_results,
            max_rounds=_settings["max_rounds"],
            on_round=_on_round,
            auto_attack=_settings["auto_attack"],
        )

    _finish(asyncio.run, _go)


def _run_file(llm):
    path = prompt("Path to scan JSON file")
    if not path or not Path(path).exists():
        error(f"File not found: {path}")
        return

    from wifi_launchpad.cli.commands.analyze import _load_scan_file
    from wifi_launchpad.services.analysis_service import AnalysisService

    scan_results = _load_scan_file(path)
    success(f"Loaded {len(scan_results.networks)} networks, {len(scan_results.clients)} clients")
    service = AnalysisService(llm)

    async def _go():
        return await service.analyze(
            scan_results,
            max_rounds=_settings["max_rounds"],
            on_round=_on_round,
            auto_attack=_settings["auto_attack"],
        )

    _finish(asyncio.run, _go)


def _finish(runner, coro_factory):
    try:
        result = runner(coro_factory())
    except KeyboardInterrupt:
        warn("Analysis interrupted.")
        pause()
        return
    if result:
        _settings["last_result"] = result
        _display_result(result)
        if _settings["auto_export"]:
            export_result(result, _settings)
    pause()


def _on_round(round_num: int, response: str):
    console.print(f"\n[bold cyan]{'─' * 60}[/bold cyan]")
    console.print(f"[bold cyan][AI Analysis — Round {round_num}][/bold cyan]")
    console.print(f"[bold cyan]{'─' * 60}[/bold cyan]")
    console.print(response)


def _display_result(result):
    console.print(f"\n[bold green]{'═' * 60}[/bold green]")
    console.print(f"[bold green]  Analysis Complete — {result.rounds} round(s)[/bold green]")
    console.print(f"[bold green]{'═' * 60}[/bold green]")

    if result.vulnerabilities:
        table = Table(title="WiFi Vulnerabilities", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("SSID", width=18)
        table.add_column("BSSID", width=18)
        table.add_column("Vulnerability", width=25)
        table.add_column("Attack", width=30)

        colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}
        for v in result.vulnerabilities:
            c = colors.get(v.severity, "white")
            table.add_row(f"[{c}]{v.severity.upper()}[/{c}]", v.ssid, v.bssid, v.name, v.attack)
        console.print(table)

    risk_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green"}
    rc = risk_colors.get(result.risk_level, "white")
    console.print(f"\n  [bold]Risk Level:[/bold] [{rc}]{result.risk_level}[/{rc}]")
    if result.summary:
        console.print(f"  [bold]Summary:[/bold] {result.summary}")


def _settings_menu():
    while True:
        divider("ANALYSIS SETTINGS")
        aa = "[green]ON[/green]" if _settings["auto_attack"] else "[red]OFF[/red]"
        ae = "[green]ON[/green]" if _settings["auto_export"] else "[red]OFF[/red]"
        mr = _settings["max_rounds"] or "default (9)"
        console.print(
            f"  [green][1][/green] Toggle auto-attack mode  ({aa})\n"
            f"  [green][2][/green] Set max rounds  ({mr})\n"
            f"  [green][3][/green] Toggle auto-export  ({ae})\n"
            f"  [green][4][/green] Back\n"
        )
        choice = prompt("spectre/analyze/settings")
        if choice == "1":
            _settings["auto_attack"] = not _settings["auto_attack"]
            state = "ON" if _settings["auto_attack"] else "OFF"
            success(f"Auto-attack mode: {state}")
            if _settings["auto_attack"]:
                warn("LLM will execute capture and crack commands automatically.")
        elif choice == "2":
            val = prompt("Max rounds (Enter for default)")
            _settings["max_rounds"] = int(val) if val.isdigit() else None
        elif choice == "3":
            _settings["auto_export"] = not _settings["auto_export"]
        elif choice == "4":
            return


def _export_last():
    result = _settings.get("last_result")
    if not result:
        warn("No analysis to export. Run an analysis first.")
        return
    export_result(result, _settings)


def export_result(result, settings_dict):
    """Export analysis result to markdown for external review."""
    from wifi_launchpad.app.settings import get_settings

    app_settings = get_settings()
    export_dir = app_settings.project_root / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = export_dir / f"spectre_analysis_{ts}.md"

    lines = [
        "# SPECTRE Analysis Export", "",
        "## Metadata",
        f"- Rounds: {result.rounds}",
        f"- Auto-attack: {'ON' if settings_dict.get('auto_attack') else 'OFF'}",
        f"- Timestamp: {result.timestamp.isoformat()}", "",
        "## Scan Data", "```", result.scan_data, "```", "",
        "## AI Analysis (Full Response)", "```", result.full_transcript or result.full_response, "```", "",
        "## Parsed Findings", "",
    ]
    for i, v in enumerate(result.vulnerabilities, 1):
        lines.extend([
            f"### VULN-{i}: {v.name}",
            f"- Severity: {v.severity.upper()}", f"- BSSID: {v.bssid}",
            f"- SSID: {v.ssid}", f"- Description: {v.description}",
            f"- Attack: {v.attack}", f"- Fix: {v.fix}",
            "- **CORRECTION**: ",
            "- **CORRECTION_TYPE**: [false_positive | severity_change | missing_vuln | confirmed]",
            "",
        ])
    lines.extend([
        f"## Risk Level: {result.risk_level}",
        f"## Summary: {result.summary}", "",
        "## Reviewer Notes", "[leave blank for reviewer to fill in]", "",
    ])
    filename.write_text("\n".join(lines))
    success(f"Exported to {filename}")


def _import_corrections():
    path = prompt("Path to reviewed .md file")
    if not path or not Path(path).exists():
        error(f"File not found: {path}")
        return

    text = Path(path).read_text()
    corrections = []
    current_vuln = None

    for line in text.splitlines():
        if line.startswith("### VULN-"):
            current_vuln = line.replace("### ", "").strip()
        elif line.startswith("- **CORRECTION**:") and current_vuln:
            val = line.split(":", 1)[1].strip()
            if val:
                corrections.append({"vuln": current_vuln, "correction": val, "type": None})
        elif line.startswith("- **CORRECTION_TYPE**:") and corrections:
            val = line.split(":", 1)[1].strip()
            for valid in ("false_positive", "severity_change", "missing_vuln", "confirmed"):
                if valid in val:
                    corrections[-1]["type"] = valid
                    break

    if not corrections:
        warn("No corrections found in file.")
        return

    success(f"Found {len(corrections)} correction(s):")
    for c in corrections:
        console.print(f"  {c['vuln']}: [{c['type'] or 'untyped'}] {c['correction'][:60]}")
    info("Corrections imported. (DB persistence coming soon)")
    pause()
