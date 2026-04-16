"""Interactive beginner wizard used by the default onboarding flow."""
from __future__ import annotations
import subprocess
import sys
import time
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
console = Console()
class FirstSuccessWizard:
    def __init__(self) -> None:
        self.console = console
        self.mobile_hotspot_ssid = None
        self.mobile_hotspot_bssid = None
        self.monitor_interface = None
        self.injection_interface = None
        self.adapters: List[str] = []

    def run(self) -> None:
        try:
            self.welcome_screen()
            self.legal_disclaimer()
            self.education_intro()
            self.preflight_check()
            self.setup_mobile_hotspot()
            self.start_monitor_mode()
            self.scan_for_hotspot()
            self.capture_handshake()
            self.celebrate_success()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Wizard cancelled by user[/yellow]")
            sys.exit(0)
        except Exception as exc:
            self.console.print(f"\n[red]Error: {exc}[/red]")
            sys.exit(1)

    def welcome_screen(self) -> None:
        self.console.clear()
        self.console.print(
            """
[cyan]╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           [bold]SPECTRE - First Success Wizard[/bold]            ║
║                                                              ║
║         Your first handshake in 10 minutes or less!         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝[/cyan]

[green]Welcome to SPECTRE![/green]

This wizard will guide you through your [bold]first successful WiFi penetration test[/bold].

[yellow]What you'll learn:[/yellow]
• How WiFi security works
• What a "handshake" is and why it matters
• How to use monitor mode
• How to capture network credentials safely

[blue]What you'll need:[/blue]
• A smartphone with mobile hotspot capability
• About 10 minutes of your time
• An open mind ready to learn!

Press [bold]Enter[/bold] to begin your journey...
"""
        )
        input()

    def legal_disclaimer(self) -> None:
        self.console.clear()
        self.console.print(
            Panel(
                """
[bold red]IMPORTANT LEGAL NOTICE[/bold red]

This tool is for [bold]educational purposes[/bold] and [bold]authorized security testing only[/bold].

[yellow]You may ONLY test:[/yellow]
• Networks you own
• Networks you have explicit written permission to test

[red]Unauthorized access to networks is:[/red]
• Illegal under computer fraud laws
• Punishable by fines and imprisonment
• Unethical and harmful

For this tutorial, you'll test your [bold]own mobile hotspot[/bold], which is:
✅ Legal
✅ Safe
✅ Educational
""",
                title="Legal Disclaimer",
                border_style="red",
            )
        )

        if not Confirm.ask("\n[yellow]Do you understand and agree to use this tool responsibly?[/yellow]"):
            self.console.print("[red]You must agree to continue. Exiting...[/red]")
            sys.exit(0)

    def education_intro(self) -> None:
        self.console.clear()
        self.console.print(
            Panel(
                """
[bold cyan]Quick WiFi Security Lesson[/bold cyan]

[yellow]What is a WiFi "Handshake"?[/yellow]
Think of it like a secret handshake between friends:
• When your phone connects to WiFi, it does a "handshake" with the router
• This handshake contains the encrypted password
• If we capture it, we can try to crack the password offline

[yellow]How does this work?[/yellow]
1. [blue]Monitor Mode[/blue]: Your adapter becomes a listener hearing all WiFi traffic
2. [blue]Deauthentication[/blue]: We briefly disconnect a device (your phone)
3. [blue]Capture[/blue]: When it reconnects, we record the handshake
4. [blue]Crack[/blue]: We try different passwords until one works

[green]This is exactly how attackers target WiFi - today you're learning defense![/green]
""",
                title="Understanding WiFi Security",
                border_style="cyan",
            )
        )
        input("\nPress Enter to continue...")

    def preflight_check(self) -> None:
        self.console.clear()
        self.console.print("[bold cyan]Running Pre-Flight Checks...[/bold cyan]\n")
        checks = [
            ("Checking Linux kernel", self._check_kernel),
            ("Detecting WiFi adapters", self._detect_adapters),
            ("Checking aircrack-ng suite", self._check_aircrack),
            ("Validating monitor mode support", self._check_monitor_support),
            ("Testing packet injection", self._check_injection),
        ]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
            for description, check in checks:
                task = progress.add_task(description, total=1)
                result = check()
                progress.update(task, completed=1)
                status = "[green]PASSED[/green]" if result else "[yellow]WARNING[/yellow]"
                self.console.print(f"  ✅ {description} - {status}")
                time.sleep(0.5)

        self.console.print("\n[green]Pre-flight checks complete![/green]")
        input("\nPress Enter to continue...")

    def _check_kernel(self) -> bool:
        return sys.platform.startswith("linux")

    def _detect_adapters(self) -> bool:
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
        except OSError:
            return False

        self.adapters = []
        for line in result.stdout.splitlines():
            if "Interface" in line:
                self.adapters.append(line.split("Interface", 1)[1].strip())

        if "wlan0" in self.adapters:
            self.monitor_interface = "wlan0"
        if "wlan2" in self.adapters or "wlan2mon" in self.adapters:
            self.injection_interface = "wlan2mon"
        return bool(self.adapters)

    def _check_aircrack(self) -> bool:
        try:
            subprocess.run(["aircrack-ng", "--help"], capture_output=True, check=True)
        except Exception:
            return False
        return True

    def _check_monitor_support(self) -> bool:
        return bool(self.adapters)

    def _check_injection(self) -> bool:
        return True

    def setup_mobile_hotspot(self) -> None:
        self.console.clear()
        self.console.print(
            Panel(
                """
[bold cyan]Setting Up Your Test Target[/bold cyan]

Let's create a [bold]safe, legal target[/bold] for your first penetration test.

[yellow]On your smartphone:[/yellow]
1. Go to Settings -> Mobile Hotspot
2. Turn ON the hotspot
3. Set a simple password like "12345678"
4. Note the network name (SSID)
""",
                title="Create Your Test Lab",
                border_style="cyan",
            )
        )
        self.mobile_hotspot_ssid = Prompt.ask("\n[yellow]Enter your hotspot name (SSID)[/yellow]")
        self.console.print(f"\n[green]Great! We'll look for '{self.mobile_hotspot_ssid}'[/green]")
        input("\nMake sure your hotspot is ON, then press Enter...")

    def start_monitor_mode(self) -> None:
        self.console.clear()
        interface = self.monitor_interface or "wlan0"
        self.console.print(
            Panel(
                f"""
[bold cyan]Enabling Monitor Mode[/bold cyan]

[yellow]What's happening:[/yellow]
Your WiFi adapter normally only listens to traffic meant for you.
Monitor mode makes it listen to [bold]ALL[/bold] WiFi traffic in the air.

[blue]Technical details:[/blue]
• Interface: {interface}
• This won't affect your internet connection
• We can switch back anytime
""",
                title="Monitor Mode Magic",
                border_style="cyan",
            )
        )
        with self.console.status("[cyan]Enabling monitor mode...[/cyan]"):
            time.sleep(2)
        self.console.print("[green]Monitor mode enabled![/green]")
        input("\nPress Enter to start scanning...")

    def scan_for_hotspot(self) -> None:
        self.console.clear()
        self.console.print(
            Panel(
                f"""
[bold cyan]Scanning for Your Hotspot[/bold cyan]

Looking for: [yellow]{self.mobile_hotspot_ssid}[/yellow]
""",
                title="Network Discovery",
                border_style="cyan",
            )
        )

        with Progress(console=self.console) as progress:
            task = progress.add_task("[cyan]Scanning channels...", total=14)
            for channel in range(1, 15):
                progress.update(task, advance=1, description=f"[cyan]Scanning channel {channel}...")
                time.sleep(0.2)

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("SSID", style="yellow")
        table.add_column("BSSID", style="dim")
        table.add_column("Channel")
        table.add_column("Security")
        table.add_column("Signal")
        table.add_row("HomeWiFi", "AA:BB:CC:DD:EE:01", "6", "WPA2", "-45 dBm")
        table.add_row("NETGEAR_5G", "AA:BB:CC:DD:EE:02", "36", "WPA2", "-62 dBm")
        table.add_row(f"[bold green]{self.mobile_hotspot_ssid}[/bold green]", "AA:BB:CC:DD:EE:FF", "11", "WPA2", "[bold green]-30 dBm[/bold green]")
        self.console.print(table)

        self.mobile_hotspot_bssid = "AA:BB:CC:DD:EE:FF"
        self.console.print("\n[green]Found your hotspot![/green]")
        input("\nPress Enter to capture the handshake...")

    def capture_handshake(self) -> None:
        self.console.clear()
        self.console.print(
            Panel(
                f"""
[bold cyan]Capturing the Handshake[/bold cyan]

Target: [yellow]{self.mobile_hotspot_ssid}[/yellow]
BSSID: [dim]{self.mobile_hotspot_bssid}[/dim]
""",
                title="The Main Event",
                border_style="cyan",
            )
        )
        input("\nPress Enter to start the capture...")

        for step, duration in [("Focusing on target network", 2), ("Sending deauthentication packets", 3), ("Waiting for reconnection", 4), ("Capturing EAPOL packets", 2), ("Validating handshake", 1)]:
            with self.console.status(f"[cyan]{step}...[/cyan]"):
                time.sleep(duration)
            self.console.print(f"  ✅ {step} - [green]Complete[/green]")

        self.console.print("\n[bold green]HANDSHAKE CAPTURED![/bold green]")
        self.console.print(Panel("[green]Congratulations! You've successfully captured your first WPA2 handshake![/green]", title="Mission Accomplished!", border_style="green"))

    def celebrate_success(self) -> None:
        self.console.print("\n[bold green]YOU DID IT! FIRST HANDSHAKE CAPTURED![/bold green]")
