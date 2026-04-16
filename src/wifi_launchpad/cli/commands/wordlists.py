"""Wordlist management commands."""

from datetime import datetime
import random
import shutil
from pathlib import Path

import click
from rich.table import Table

from wifi_launchpad.app.settings import WORDLIST_CATEGORIES, WORDLIST_IMPORT_CATEGORY_MAP, get_settings
from wifi_launchpad.cli.common import console


@click.group()
def wordlists():
    """Manage WiFi password wordlists."""


@wordlists.command("list")
def wordlist_list():
    """List available wordlists."""

    wordlist_dir = get_settings().wordlist_dir
    if not wordlist_dir.exists():
        console.print("[red]Wordlists directory not found![/red]")
        return

    table = Table(title="Available Wordlists", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="yellow")
    table.add_column("Category", style="green")
    table.add_column("Passwords", style="white")
    table.add_column("File Size", style="dim")
    unique_passwords = set()

    for category in WORDLIST_CATEGORIES:
        category_path = wordlist_dir / category
        if not category_path.exists():
            continue
        for file in category_path.glob("*.txt"):
            with open(file, "r", encoding="utf-8") as handle:
                passwords = [line.rstrip("\n") for line in handle]
            unique_passwords.update(password for password in passwords if password)
            size = file.stat().st_size
            size_str = f"{size} B" if size < 1024 else (f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB")
            table.add_row(file.stem, category, str(len(passwords)), size_str)

    master_file = wordlist_dir / "master-wifi-wordlist.txt"
    if master_file.exists():
        with open(master_file, "r", encoding="utf-8") as handle:
            count = sum(1 for _ in handle)
        size = master_file.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
        table.add_row("[bold]master-wifi-wordlist[/bold]", "[bold]ALL[/bold]", f"[bold]{count}[/bold]", f"[bold]{size_str}[/bold]")

    console.print(table)
    console.print(f"\n[cyan]Total unique passwords: {len(unique_passwords)}[/cyan]")


@wordlists.command("generate")
@click.option("--type", "-t", "wordlist_type", type=click.Choice(["dates", "phones", "patterns", "custom"]), default="patterns", help="Type of wordlist to generate")
@click.option("--output", "-o", help="Output file name")
@click.option("--count", "-c", type=int, default=1000, help="Number of passwords to generate")
def wordlist_generate(wordlist_type, output, count):
    """Generate custom wordlists."""

    wordlist_dir = get_settings().wordlist_dir
    console.print(f"[cyan]Generating {wordlist_type} wordlist with {count} passwords...[/cyan]")
    passwords = set()

    if wordlist_type == "dates":
        current_year = datetime.now().year
        for year in range(current_year - 5, current_year + 2):
            for month in range(1, 13):
                passwords.update({f"{month:02d}{year}", f"{year}{month:02d}", f"password{year}", f"wifi{year}"})
                if len(passwords) >= count:
                    break
    elif wordlist_type == "phones":
        area_codes = ["212", "213", "312", "415", "510", "619", "714", "818", "925"]
        while len(passwords) < count:
            passwords.add(f"{random.choice(area_codes)}{random.randint(1000000, 9999999)}")
    elif wordlist_type == "patterns":
        for word in ["wifi", "internet", "network", "router", "admin", "password", "home", "guest"]:
            for num in range(100):
                passwords.update({f"{word}{num:03d}", f"{word}@{num}", f"{num}{word}"})
                if len(passwords) >= count:
                    break
    else:
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        while len(passwords) < count:
            length = random.randint(8, 12)
            passwords.add("".join(random.choice(chars) for _ in range(length)))

    output_name = output or f"custom-{wordlist_type}-{datetime.now().strftime('%Y%m%d')}.txt"
    output_path = wordlist_dir / "generated" / output_name
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for password in sorted(list(passwords)[:count]):
            handle.write(password + "\n")

    console.print(f"[green]Generated {len(passwords)} passwords[/green]")
    console.print(f"[green]Saved to: {output_path}[/green]")


@wordlists.command("import")
@click.argument("file", type=click.Path(exists=True))
@click.option("--category", "-c", type=click.Choice(sorted(WORDLIST_IMPORT_CATEGORY_MAP)), default="generated", help="Category for imported wordlist")
def wordlist_import(file, category):
    """Import a custom wordlist."""

    wordlist_dir = get_settings().wordlist_dir
    source = Path(file)
    dest_dir = wordlist_dir / WORDLIST_IMPORT_CATEGORY_MAP[category]
    dest_dir.mkdir(exist_ok=True)
    dest_file = dest_dir / source.name

    with open(source, "r", encoding="utf-8") as handle:
        count = sum(1 for _ in handle)

    shutil.copy2(source, dest_file)
    console.print(f"[green]Imported {count} passwords[/green]")
    console.print(f"[green]Saved to: {dest_file}[/green]")

    console.print("[cyan]Updating master wordlist...[/cyan]")
    master_file = wordlist_dir / "master-wifi-wordlist.txt"
    all_passwords = set()
    if master_file.exists():
        with open(master_file, "r", encoding="utf-8") as handle:
            all_passwords.update(line.strip() for line in handle)
    with open(source, "r", encoding="utf-8") as handle:
        all_passwords.update(line.strip() for line in handle)
    with open(master_file, "w", encoding="utf-8") as handle:
        for password in sorted(all_passwords):
            if password:
                handle.write(password + "\n")

    console.print(f"[green]Master wordlist updated: {len(all_passwords)} total passwords[/green]")


@wordlists.command("stats")
def wordlist_stats():
    """Show wordlist statistics and success rates."""

    wordlist_dir = get_settings().wordlist_dir
    console.print("[cyan]Wordlist Statistics[/cyan]\n")
    stats = {"total_passwords": 0, "total_files": 0, "by_category": {}, "largest_file": None, "largest_size": 0}

    for category in WORDLIST_CATEGORIES:
        category_path = wordlist_dir / category
        cat_passwords = 0
        cat_files = 0
        if category_path.exists():
            for file in category_path.glob("*.txt"):
                with open(file, "r", encoding="utf-8") as handle:
                    count = sum(1 for _ in handle)
                cat_passwords += count
                cat_files += 1
                stats["total_passwords"] += count
                stats["total_files"] += 1
                size = file.stat().st_size
                if size > stats["largest_size"]:
                    stats["largest_size"] = size
                    stats["largest_file"] = file.name
        stats["by_category"][category] = {"passwords": cat_passwords, "files": cat_files}

    console.print(f"Total Passwords: [yellow]{stats['total_passwords']:,}[/yellow]")
    console.print(f"Total Files: [yellow]{stats['total_files']}[/yellow]")
    console.print(f"Largest File: [yellow]{stats['largest_file']}[/yellow] ({stats['largest_size'] / 1024:.1f} KB)\n")

    table = Table(title="Passwords by Category", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="green")
    table.add_column("Passwords", style="yellow")
    table.add_column("Files", style="white")
    for category, data in stats["by_category"].items():
        table.add_row(category, str(data["passwords"]), str(data["files"]))
    console.print(table)


def register_wordlist_commands(cli):
    """Register the wordlist command group."""

    cli.add_command(wordlists)
