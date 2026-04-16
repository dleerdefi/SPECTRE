"""Cracking workflow commands."""

import sys

import click
from rich.panel import Panel
from rich.table import Table

from wifi_launchpad.cli.common import console


def register_crack_commands(cli):
    """Register cracking CLI commands."""

    @cli.command()
    @click.option("--hash-file", "-f", help="Path to .22000 hash file")
    @click.option("--wordlist", "-w", multiple=True, help="Wordlist path (repeatable)")
    @click.option("--rules", "-r", help="Hashcat rules file")
    @click.option("--timeout", "-t", type=int, default=None, help="Timeout per file in seconds")
    @click.option(
        "--auto", "auto_mode", is_flag=True, help="Auto-crack all .22000 files in capture directory"
    )
    def crack(hash_file, wordlist, rules, timeout, auto_mode):
        """Crack WPA/WPA2 hashes with hashcat."""

        from wifi_launchpad.app.settings import get_settings
        from wifi_launchpad.providers.external.hashcat import HashcatProvider
        from wifi_launchpad.services.crack_service import CrackService

        timeout = timeout or get_settings().crack.timeout

        if not HashcatProvider.is_available():
            console.print("[red]hashcat is not installed or not in PATH[/red]")
            console.print("Install with: [yellow]sudo apt install hashcat[/yellow]")
            sys.exit(1)

        service = CrackService()

        if auto_mode:
            console.print(
                Panel(
                    "[bold cyan]Auto-Crack Mode[/bold cyan]\n\n"
                    "Scanning capture directory for .22000 hash files...",
                    border_style="cyan",
                )
            )

            results = service.auto_crack_directory(timeout_per_file=timeout)

            if not results:
                console.print("[yellow]No .22000 files found in capture directory[/yellow]")
                console.print(
                    f"[dim]Looked in: {service.settings.capture_dir}[/dim]"
                )
                return

            table = Table(
                title="Crack Results", show_header=True, header_style="bold cyan"
            )
            table.add_column("Hash File")
            table.add_column("Status")
            table.add_column("Password", style="green")
            table.add_column("Time")
            table.add_column("Method")

            cracked_count = 0
            for r in results:
                if r.cracked:
                    cracked_count += 1
                    status = "[bold green]CRACKED[/bold green]"
                    pw = r.password or ""
                else:
                    status = "[red]Not cracked[/red]"
                    pw = ""

                table.add_row(
                    r.hash_file or "?",
                    status,
                    pw,
                    f"{r.crack_time:.1f}s" if r.crack_time else "-",
                    r.method,
                )

            console.print(table)
            console.print(
                f"\n[bold]{cracked_count}/{len(results)} hashes cracked[/bold]"
            )
            return

        if not hash_file:
            console.print("[red]Specify --hash-file or use --auto[/red]")
            sys.exit(1)

        console.print(
            Panel(
                f"[bold cyan]Cracking Hash[/bold cyan]\n\n"
                f"File: [yellow]{hash_file}[/yellow]\n"
                f"Timeout: [yellow]{timeout}s[/yellow]",
                border_style="cyan",
            )
        )

        wordlists = list(wordlist) if wordlist else None
        console.print("[cyan]Running hashcat...[/cyan]")

        result = service.crack_hash(
            hash_file=hash_file,
            wordlists=wordlists,
            rules=rules,
            timeout=timeout,
        )

        if result.cracked:
            console.print(f"\n[bold green]PASSWORD FOUND![/bold green]\n")

            table = Table(show_header=False, box=None)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="yellow")
            table.add_row("Password", f"[bold green]{result.password}[/bold green]")
            table.add_row("Method", result.method)
            table.add_row("Time", f"{result.crack_time:.1f}s" if result.crack_time else "-")
            table.add_row("Wordlist", result.wordlist_used or "built-in chain")
            console.print(table)
        else:
            console.print(f"\n[yellow]Password not found[/yellow]")
            console.print(f"[dim]Method: {result.method}, Time: {result.crack_time:.1f}s[/dim]")
            console.print("\n[cyan]Try:[/cyan]")
            console.print("  - A larger wordlist (e.g., rockyou.txt)")
            console.print("  - Rules: [yellow]--rules /usr/share/hashcat/rules/best64.rule[/yellow]")
            console.print("  - More time: [yellow]--timeout 3600[/yellow]")
