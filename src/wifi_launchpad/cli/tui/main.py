"""SPECTRE TUI — main menu loop."""

import sys

from wifi_launchpad.cli.common import console, print_banner
from wifi_launchpad.cli.tui.helpers import prompt, pause, warn


def run_tui():
    """Launch the SPECTRE interactive TUI."""
    while True:
        print_banner()
        console.print(
            "  [green][1][/green]  Recon & Survey       [dim]— passive WiFi discovery[/dim]\n"
            "  [green][2][/green]  AI Analysis          [dim]— LLM-powered vuln assessment[/dim]\n"
            "  [green][3][/green]  Attack Campaign      [dim]— automated pwn chain[/dim]\n"
            "  [green][4][/green]  Crack Hashes         [dim]— hashcat with HW profiles[/dim]\n"
            "  [green][5][/green]  Browse History       [dim]— view current & past runs[/dim]\n"
            "  [green][6][/green]  Cases & Reports      [dim]— manage evidence[/dim]\n"
            "  [green][7][/green]  System Check         [dim]— doctor / adapters[/dim]\n"
            "  [green][8][/green]  Exit\n"
        )

        choice = prompt("spectre")

        if choice == "1":
            from wifi_launchpad.cli.tui.recon import recon_menu
            recon_menu()
        elif choice == "2":
            from wifi_launchpad.cli.tui.analysis import analysis_menu
            analysis_menu()
        elif choice == "3":
            from wifi_launchpad.cli.tui.attack import attack_menu
            attack_menu()
        elif choice == "4":
            from wifi_launchpad.cli.tui.crack import crack_menu
            crack_menu()
        elif choice == "5":
            from wifi_launchpad.cli.tui.history import history_menu
            history_menu()
        elif choice == "6":
            from wifi_launchpad.cli.tui.cases import case_menu
            case_menu()
        elif choice == "7":
            from wifi_launchpad.cli.tui.system import system_menu
            system_menu()
        elif choice == "8":
            console.print("\n[red]SPECTRE shutting down.[/red]\n")
            sys.exit(0)
        else:
            warn("Invalid choice.")
            pause()
