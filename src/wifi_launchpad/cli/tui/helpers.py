"""Shared TUI helper functions."""

from wifi_launchpad.cli.common import console


def prompt(label: str = "spectre") -> str:
    """Cyan-colored input prompt."""
    try:
        return input(f"\033[36m{label}> \033[0m").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def pause():
    input("\033[90mPress Enter to continue...\033[0m")


def divider(label: str = ""):
    if label:
        console.print(f"\n[yellow]{'─' * 16} {label} {'─' * 16}[/yellow]")
    else:
        console.print(f"[dim]{'─' * 50}[/dim]")


def success(msg: str):
    console.print(f"[green][+] {msg}[/green]")


def warn(msg: str):
    console.print(f"[yellow][!] {msg}[/yellow]")


def info(msg: str):
    console.print(f"[cyan][*] {msg}[/cyan]")


def error(msg: str):
    console.print(f"[red][!] {msg}[/red]")
