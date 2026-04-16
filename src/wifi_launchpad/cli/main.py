"""Packaged CLI entrypoint."""

import os
import sys

import click
from rich.panel import Panel

from wifi_launchpad.cli.commands import (
    register_analyze_commands,
    register_autopwn_commands,
    register_capture_commands,
    register_case_commands,
    register_crack_commands,
    register_quickstart_commands,
    register_survey_commands,
    register_system_commands,
    register_wordlist_commands,
)
from wifi_launchpad.cli.common import console


@click.group(invoke_without_command=True)
@click.option("--advanced", is_flag=True, help="Skip wizard and use advanced mode")
@click.pass_context
def cli(ctx, advanced):
    """
    SPECTRE — wireless tactical assessment toolkit.

    By default, launches the interactive TUI.
    Use --advanced for direct command access.
    """

    if ctx.invoked_subcommand is not None:
        return
    if advanced:
        show_advanced_menu()
        return

    from wifi_launchpad.cli.tui import run_tui

    run_tui()


def show_advanced_menu():
    """Display the advanced mode menu."""

    console.print(
        Panel(
            "[bold cyan]SPECTRE — Advanced Mode[/bold cyan]\n\n"
            "Available commands:\n\n"
            "[yellow]System:[/yellow]\n"
            "  doctor       - Inspect provider/tool readiness\n"
            "  preflight    - Run system checks\n"
            "  adapters     - List WiFi adapters\n"
            "  monitor      - Enable monitor mode\n\n"
            "[yellow]Operations:[/yellow]\n"
            "  analyze      - AI-powered security analysis (optional LLM)\n"
            "  survey       - Run passive survey and store evidence\n"
            "  autopwn      - Persistent campaign: scan -> capture -> crack\n"
            "  quickcapture - Automated scan -> capture workflow\n"
            "  scan         - Scan for networks\n"
            "  capture      - Capture handshake (manual)\n"
            "  crack        - Crack hashes with hashcat\n\n"
            "[yellow]Casework:[/yellow]\n"
            "  cases        - Create and manage case files\n"
            "  report       - Generate a case summary report\n\n"
            "[yellow]Learning:[/yellow]\n"
            "  wizard       - Launch beginner wizard\n"
            "  sandbox      - Safe mobile hotspot test\n\n"
            "Use 'spectre COMMAND --help' for direct command access.",
            border_style="cyan",
        )
    )


def main():
    """Console-script friendly wrapper."""

    if len(sys.argv) > 1 and sys.argv[1] in ["monitor", "capture", "scan", "survey"] and os.geteuid() != 0:
        console.print("[yellow]Note: Some operations may require sudo privileges[/yellow]")

    cli()


register_analyze_commands(cli)
register_system_commands(cli)
register_survey_commands(cli)
register_capture_commands(cli)
register_crack_commands(cli)
register_autopwn_commands(cli)
register_quickstart_commands(cli)
register_case_commands(cli)
register_wordlist_commands(cli)
