#!/usr/bin/env python3
"""
First Success Wizard - REAL Implementation

This wizard actually captures a real handshake using the mobile hotspot method.
Combines education with actual functionality.
"""

import os
import sys
import time
import asyncio
import subprocess
from typing import Optional, Dict, List
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner import NetworkScanner, ScanResult
from core.capture import CaptureManager, CaptureConfig, HandshakeValidator
from core.adapters import AdapterManager
from services.scanner_service import ScannerService, ScanConfig, ScanMode

console = Console()


class RealFirstSuccessWizard:
    """Interactive wizard that actually works!"""

    def __init__(self):
        self.console = console
        self.adapter_manager = AdapterManager()
        self.scanner_service = ScannerService()

        # Wizard state
        self.monitor_interface: Optional[str] = None
        self.mobile_hotspot_ssid: Optional[str] = None
        self.mobile_hotspot_bssid: Optional[str] = None
        self.mobile_hotspot_channel: Optional[int] = None
        self.captured_handshake: Optional[str] = None

    def run(self):
        """Main wizard entry point"""
        try:
            self.welcome_screen()
            self.legal_disclaimer()
            self.education_intro()

            # Real operations start here
            if not self.setup_adapter():
                self.console.print("[red]Failed to set up adapter. Please check your hardware.[/red]")
                return

            self.setup_mobile_hotspot()

            if not self.find_hotspot():
                self.console.print("[red]Could not find your hotspot. Please check it's enabled.[/red]")
                return

            if self.capture_real_handshake():
                self.celebrate_success()
            else:
                self.console.print("[yellow]Handshake capture failed. Try moving closer to your phone.[/yellow]")

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Wizard cancelled by user[/yellow]")
            sys.exit(0)
        except Exception as e:
            self.console.print(f"\n[red]Error: {e}[/red]")
            sys.exit(1)

    def welcome_screen(self):
        """Display welcome message"""
        self.console.clear()

        welcome_text = """
[cyan]╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           [bold]WiFi Launchpad - First Success Wizard[/bold]            ║
║                                                              ║
║         Your first handshake in 10 minutes or less!         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝[/cyan]

[green]Welcome to WiFi Launchpad![/green] 🚀

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
        self.console.print(welcome_text)
        input()

    def legal_disclaimer(self):
        """Display legal disclaimer"""
        self.console.clear()

        disclaimer = Panel("""
[bold red]⚠️  IMPORTANT LEGAL NOTICE ⚠️[/bold red]

This tool is for [bold]educational purposes[/bold] and [bold]authorized security testing only[/bold].

[yellow]You may ONLY test:[/yellow]
• Networks you own
• Networks you have explicit written permission to test

[red]Unauthorized access to networks is:[/red]
• Illegal under computer fraud laws
• Punishable by fines and imprisonment
• Unethical and harmful

For this tutorial, you'll test your [bold]own mobile hotspot[/bold], which is:
✅ Legal (it's your network)
✅ Safe (no one else is affected)
✅ Educational (you'll learn the fundamentals)
""", title="Legal Disclaimer", border_style="red")

        self.console.print(disclaimer)

        if not Confirm.ask("\n[yellow]Do you understand and agree to use this tool responsibly?[/yellow]"):
            self.console.print("[red]You must agree to continue. Exiting...[/red]")
            sys.exit(0)

    def education_intro(self):
        """Educational introduction"""
        self.console.clear()

        self.console.print(Panel("""
[bold cyan]📚 Quick WiFi Security Lesson[/bold cyan]

[yellow]What is a WiFi "Handshake"?[/yellow]
Think of it like a secret handshake between friends:
• When your phone connects to WiFi, it does a "handshake" with the router
• This handshake contains the encrypted password
• If we capture this handshake, we can try to crack the password offline

[yellow]How does this work?[/yellow]
1. [blue]Monitor Mode[/blue]: Your adapter becomes a "listener" hearing all WiFi traffic
2. [blue]Deauthentication[/blue]: We briefly disconnect a device (your phone)
3. [blue]Capture[/blue]: When it reconnects, we record the handshake
4. [blue]Crack[/blue]: We try different passwords until one works

[green]This is exactly how hackers attack WiFi - but today, you're learning defense![/green]
""", title="Understanding WiFi Security", border_style="cyan"))

        input("\nPress Enter to continue...")

    def setup_adapter(self) -> bool:
        """Set up WiFi adapter with monitor mode"""
        self.console.clear()
        self.console.print("[bold cyan]🔍 Setting Up WiFi Adapter[/bold cyan]\n")

        with self.console.status("[cyan]Detecting adapters...[/cyan]"):
            adapters = self.adapter_manager.discover_adapters()

        if not adapters:
            self.console.print("[red]❌ No WiFi adapters found![/red]")
            self.console.print("\nPlease connect a WiFi adapter and try again.")
            self.console.print("Recommended: ALFA AWUS036ACH or AWUS036AXML")
            return False

        # Display found adapters
        table = Table(title="WiFi Adapters Found", show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim")
        table.add_column("Interface", style="green")
        table.add_column("Chipset", style="yellow")
        table.add_column("Driver")
        table.add_column("Monitor", style="cyan")

        for i, adapter in enumerate(adapters, 1):
            monitor_support = "✅" if adapter.monitor_mode else "❌"
            table.add_row(
                str(i),
                adapter.interface,
                adapter.chipset or "Unknown",
                adapter.driver or "Unknown",
                monitor_support
            )

        self.console.print(table)

        # Select adapter
        if len(adapters) == 1:
            selected = adapters[0]
            self.console.print(f"\n[green]Using {selected.interface}[/green]")
        else:
            choice = Prompt.ask("\nSelect adapter number", default="1")
            try:
                selected = adapters[int(choice) - 1]
            except (ValueError, IndexError):
                selected = adapters[0]

        # Enable monitor mode
        self.console.print(f"\n[cyan]Enabling monitor mode on {selected.interface}...[/cyan]")

        if self.adapter_manager.enable_monitor_mode(selected):
            self.monitor_interface = selected.interface
            self.console.print(f"[green]✅ Monitor mode enabled on {self.monitor_interface}[/green]")
            return True
        else:
            self.console.print(f"[red]❌ Failed to enable monitor mode[/red]")
            return False

    def setup_mobile_hotspot(self):
        """Guide user to set up mobile hotspot"""
        self.console.clear()

        self.console.print(Panel("""
[bold cyan]📱 Setting Up Your Test Target[/bold cyan]

Let's create a [bold]safe, legal target[/bold] for your first penetration test!

[yellow]On your smartphone:[/yellow]
1. Go to Settings → Mobile Hotspot (or Personal Hotspot on iPhone)
2. Turn ON the hotspot
3. Set a simple password like "12345678" (we'll crack it easily!)
4. Note the network name (SSID)

[green]Why use your hotspot?[/green]
• It's YOUR network (100% legal)
• No one else is affected
• Perfect for learning
• You control everything
""", title="Create Your Test Lab", border_style="cyan"))

        self.mobile_hotspot_ssid = Prompt.ask("\n[yellow]Enter your hotspot name (SSID)[/yellow]")

        self.console.print(f"\n[green]Great! We'll look for '{self.mobile_hotspot_ssid}'[/green]")
        input("\nMake sure your hotspot is ON, then press Enter...")

    def find_hotspot(self) -> bool:
        """Scan for and find the mobile hotspot"""
        self.console.clear()
        self.console.print(Panel(f"""
[bold cyan]🔍 Scanning for Your Hotspot[/bold cyan]

Looking for: [yellow]{self.mobile_hotspot_ssid}[/yellow]

[blue]What's happening:[/blue]
• Listening on all WiFi channels
• Looking for beacon frames (WiFi "advertisements")
• Identifying your hotspot among all networks
""", title="Network Discovery", border_style="cyan"))

        # Use real scanner
        scanner = NetworkScanner(self.monitor_interface)

        self.console.print("\n[cyan]Scanning for networks...[/cyan]")

        # Quick scan for 15 seconds
        with Progress(console=self.console) as progress:
            task = progress.add_task("[cyan]Scanning channels...", total=15)

            scanner.start_scan(write_interval=2)

            for i in range(15):
                time.sleep(1)
                progress.update(task, advance=1)

            results = scanner.stop_scan()

        # Display found networks
        if not results.networks:
            self.console.print("[red]No networks found. Please check your adapter.[/red]")
            return False

        self.console.print(f"\n[green]Found {len(results.networks)} networks:[/green]")

        # Create table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("SSID", style="yellow")
        table.add_column("BSSID", style="dim")
        table.add_column("Channel")
        table.add_column("Security")
        table.add_column("Signal")

        # Find our hotspot
        hotspot_found = None
        for network in sorted(results.networks, key=lambda n: n.signal_strength, reverse=True)[:10]:
            is_target = network.ssid == self.mobile_hotspot_ssid
            style = "bold green" if is_target else ""

            table.add_row(
                f"[{style}]{network.ssid}[/{style}]",
                network.bssid,
                str(network.channel),
                network.encryption.value,
                f"{network.signal_strength} dBm"
            )

            if is_target:
                hotspot_found = network

        self.console.print(table)

        if hotspot_found:
            self.mobile_hotspot_bssid = hotspot_found.bssid
            self.mobile_hotspot_channel = hotspot_found.channel
            self.console.print(f"\n[green]✅ Found your hotspot on channel {self.mobile_hotspot_channel}![/green]")
            return True
        else:
            self.console.print(f"\n[yellow]⚠️  Hotspot '{self.mobile_hotspot_ssid}' not found[/yellow]")
            self.console.print("Please check that your hotspot is enabled and try again.")
            return False

    def capture_real_handshake(self) -> bool:
        """Actually capture a handshake"""
        self.console.clear()

        self.console.print(Panel(f"""
[bold cyan]🎯 Capturing the Handshake[/bold cyan]

Target: [yellow]{self.mobile_hotspot_ssid}[/yellow]
BSSID: [dim]{self.mobile_hotspot_bssid}[/dim]
Channel: [dim]{self.mobile_hotspot_channel}[/dim]

[yellow]The Process:[/yellow]
1. Send deauth packets to disconnect your phone
2. Your phone will automatically reconnect
3. During reconnection, we capture the "handshake"
4. This handshake contains the encrypted password

[red]Note:[/red] Your phone will briefly lose connection - this is normal!
""", title="The Main Event", border_style="cyan"))

        input("\nPress Enter to start the capture...")

        # Configure capture
        config = CaptureConfig(
            target_bssid=self.mobile_hotspot_bssid,
            target_channel=self.mobile_hotspot_channel,
            target_ssid=self.mobile_hotspot_ssid,
            capture_timeout=60,  # 1 minute timeout
            deauth_count=3,
            deauth_interval=5,
            min_quality_score=30.0  # Lower threshold for mobile hotspot
        )

        # Create capture manager
        capture_manager = CaptureManager(self.monitor_interface)

        # Show progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Capturing handshake...", total=None)

            # Status updates
            status_messages = {
                "capturing": "Monitoring for handshake...",
                "deauthing": "Sending deauth packets...",
                "validating": "Validating captured data...",
                "success": "[green]Handshake captured![/green]"
            }

            def update_status(status):
                progress.update(task, description=status_messages.get(status.value, status.value))

            capture_manager.on_status_change = update_status

            # Capture!
            success, handshake = capture_manager.capture_handshake(config)

        if success and handshake:
            self.captured_handshake = handshake.pcap_file

            # Validate
            validator = HandshakeValidator()
            validation = validator.validate_pcap(handshake.pcap_file)

            self.console.print("\n[bold green]🎉 HANDSHAKE CAPTURED! 🎉[/bold green]")

            # Show details
            table = Table(show_header=False, box=None)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="yellow")

            table.add_row("Network", self.mobile_hotspot_ssid)
            table.add_row("Quality", f"{handshake.quality_score:.0f}/100")
            table.add_row("EAPOL Packets", str(handshake.eapol_packets))
            table.add_row("Capture Time", f"{handshake.time_to_capture:.1f} seconds")
            table.add_row("Status", "✅ Valid" if validation.is_valid else "⚠️  Partial")

            self.console.print(table)
            return True
        else:
            self.console.print("\n[yellow]Handshake capture failed[/yellow]")
            return False

    def celebrate_success(self):
        """Celebrate the user's success"""
        self.console.print(Panel("""
[green]Congratulations! You've successfully captured your first WPA2 handshake![/green]

[yellow]What you've learned:[/yellow]
✅ How to enable monitor mode
✅ How to scan for networks
✅ How to capture a WPA2 handshake
✅ The basics of WiFi security

[cyan]What's next:[/cyan]
• The handshake is saved in /tmp/wifi-launchpad/captures/
• You could now use tools like hashcat to crack it
• Since you know the password, you can verify it works!
• Try the advanced mode for more features

[bold]You're no longer a beginner - you're a WiFi security researcher![/bold]
""", title="Mission Accomplished!", border_style="green"))

        self.console.print("\n" + "🎉" * 20)
        self.console.print("[bold green]     YOU DID IT! FIRST HANDSHAKE CAPTURED!     [/bold green]")
        self.console.print("🎉" * 20)

        self.console.print("""
[cyan]Want to learn more?[/cyan]

Try these next:
• Run './launch.sh' and choose option 4 for advanced mode
• Test different networks (with permission!)
• Learn about WPS attacks
• Explore evil twin attacks

[yellow]Remember:[/yellow] With great power comes great responsibility!
Always use your skills ethically and legally.

[green]Welcome to the WiFi security community! 🚀[/green]
""")


def main():
    """Entry point"""
    wizard = RealFirstSuccessWizard()
    wizard.run()


if __name__ == "__main__":
    main()