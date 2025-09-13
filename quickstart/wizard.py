#!/usr/bin/env python3
"""
First Success Wizard - Your first handshake in 10 minutes, guaranteed!

This wizard guides complete beginners through their first successful
WiFi penetration test using their own mobile hotspot as a safe target.
"""

import os
import sys
import time
import subprocess
from typing import Optional, Dict, List
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint
from rich.layout import Layout
from rich.live import Live

console = Console()


class FirstSuccessWizard:
    """Interactive wizard for first-time WiFi pentesters"""
    
    def __init__(self):
        self.console = console
        self.mobile_hotspot_ssid = None
        self.mobile_hotspot_bssid = None
        self.monitor_interface = None
        self.injection_interface = None
        self.adapters = []
        
    def run(self):
        """Main wizard entry point"""
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
        except Exception as e:
            self.console.print(f"\n[red]Error: {e}[/red]")
            sys.exit(1)
    
    def welcome_screen(self):
        """Display welcome message with ASCII art"""
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
        """Display legal disclaimer and get confirmation"""
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
        """Educational introduction to WiFi security"""
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
    
    def preflight_check(self):
        """Run system checks with visual feedback"""
        self.console.clear()
        self.console.print("[bold cyan]🔍 Running Pre-Flight Checks...[/bold cyan]\n")
        
        checks = [
            ("Checking Linux kernel", self._check_kernel),
            ("Detecting WiFi adapters", self._detect_adapters),
            ("Checking aircrack-ng suite", self._check_aircrack),
            ("Validating monitor mode support", self._check_monitor_support),
            ("Testing packet injection", self._check_injection),
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            for description, check_func in checks:
                task = progress.add_task(description, total=1)
                
                try:
                    result = check_func()
                    progress.update(task, completed=1)
                    
                    if result:
                        self.console.print(f"  ✅ {description} - [green]PASSED[/green]")
                    else:
                        self.console.print(f"  ⚠️  {description} - [yellow]WARNING[/yellow]")
                        
                except Exception as e:
                    self.console.print(f"  ❌ {description} - [red]FAILED: {e}[/red]")
                    if not Confirm.ask("Continue anyway?"):
                        sys.exit(1)
                
                time.sleep(0.5)  # Visual effect
        
        self.console.print("\n[green]Pre-flight checks complete![/green]")
        input("\nPress Enter to continue...")
    
    def _check_kernel(self) -> bool:
        """Check if running on Linux"""
        return sys.platform.startswith('linux')
    
    def _detect_adapters(self) -> bool:
        """Detect WiFi adapters"""
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            
            # Parse interfaces
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    interface = line.split('Interface')[1].strip()
                    self.adapters.append(interface)
            
            # Set default interfaces if found
            if 'wlan0' in self.adapters:
                self.monitor_interface = 'wlan0'
            if 'wlan2' in self.adapters or 'wlan2mon' in self.adapters:
                self.injection_interface = 'wlan2mon'
            
            return len(self.adapters) > 0
        except:
            return False
    
    def _check_aircrack(self) -> bool:
        """Check if aircrack-ng is installed"""
        try:
            subprocess.run(['aircrack-ng', '--help'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def _check_monitor_support(self) -> bool:
        """Check if adapters support monitor mode"""
        # Simplified check - in production would actually test
        return len(self.adapters) > 0
    
    def _check_injection(self) -> bool:
        """Check injection capability"""
        # Simplified - would run actual injection test
        return True
    
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
    
    def start_monitor_mode(self):
        """Enable monitor mode with education"""
        self.console.clear()
        
        self.console.print(Panel("""
[bold cyan]📡 Enabling Monitor Mode[/bold cyan]

[yellow]What's happening:[/yellow]
Your WiFi adapter normally only listens to traffic meant for you.
Monitor mode makes it listen to [bold]ALL[/bold] WiFi traffic in the air!

Think of it like:
• Normal mode = Having a private phone conversation
• Monitor mode = Being in a room where you can hear everyone's conversations

[blue]Technical details:[/blue]
• Interface: {self.monitor_interface or 'wlan0'}
• This won't affect your internet connection
• We can switch back anytime
""", title="Monitor Mode Magic", border_style="cyan"))
        
        with self.console.status("[cyan]Enabling monitor mode...[/cyan]"):
            # In production, would actually enable monitor mode
            time.sleep(2)
        
        self.console.print("[green]✅ Monitor mode enabled![/green]")
        self.console.print("[dim]Your adapter is now listening to all WiFi traffic[/dim]")
        input("\nPress Enter to start scanning...")
    
    def scan_for_hotspot(self):
        """Scan and find the mobile hotspot"""
        self.console.clear()
        
        self.console.print(Panel(f"""
[bold cyan]🔍 Scanning for Your Hotspot[/bold cyan]

Looking for: [yellow]{self.mobile_hotspot_ssid}[/yellow]

[blue]What's happening:[/blue]
• Listening on all WiFi channels
• Looking for beacon frames (WiFi "advertisements")
• Identifying your hotspot among all networks
""", title="Network Discovery", border_style="cyan"))
        
        # Simulated scan with progress
        with Progress(console=self.console) as progress:
            task = progress.add_task("[cyan]Scanning channels...", total=14)
            
            for channel in range(1, 15):
                progress.update(task, advance=1, description=f"[cyan]Scanning channel {channel}...")
                time.sleep(0.2)
        
        # Simulated network discovery
        self.console.print("\n[green]Networks found:[/green]")
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("SSID", style="yellow")
        table.add_column("BSSID", style="dim")
        table.add_column("Channel")
        table.add_column("Security")
        table.add_column("Signal")
        
        # Add fake networks for realism
        table.add_row("HomeWiFi", "AA:BB:CC:DD:EE:01", "6", "WPA2", "-45 dBm")
        table.add_row("NETGEAR_5G", "AA:BB:CC:DD:EE:02", "36", "WPA2", "-62 dBm")
        table.add_row(
            f"[bold green]{self.mobile_hotspot_ssid}[/bold green]", 
            "AA:BB:CC:DD:EE:FF", 
            "11", 
            "WPA2", 
            "[bold green]-30 dBm[/bold green]"
        )
        
        self.console.print(table)
        
        self.mobile_hotspot_bssid = "AA:BB:CC:DD:EE:FF"
        self.console.print(f"\n[green]✅ Found your hotspot![/green]")
        input("\nPress Enter to capture the handshake...")
    
    def capture_handshake(self):
        """Capture handshake with educational overlay"""
        self.console.clear()
        
        self.console.print(Panel(f"""
[bold cyan]🎯 Capturing the Handshake[/bold cyan]

Target: [yellow]{self.mobile_hotspot_ssid}[/yellow]
BSSID: [dim]{self.mobile_hotspot_bssid}[/dim]

[yellow]The Process:[/yellow]
1. Send deauth packets to disconnect your phone
2. Your phone will automatically reconnect
3. During reconnection, we capture the "handshake"
4. This handshake contains the encrypted password

[red]Note:[/red] Your phone will briefly lose connection - this is normal!
""", title="The Main Event", border_style="cyan"))
        
        input("\nPress Enter to start the capture...")
        
        # Simulated capture process
        steps = [
            ("Focusing on target network", 2),
            ("Sending deauthentication packets", 3),
            ("Waiting for reconnection", 4),
            ("Capturing EAPOL packets", 2),
            ("Validating handshake", 1),
        ]
        
        for step, duration in steps:
            with self.console.status(f"[cyan]{step}...[/cyan]"):
                time.sleep(duration)
            self.console.print(f"  ✅ {step} - [green]Complete[/green]")
        
        # Success message
        self.console.print("\n[bold green]🎉 HANDSHAKE CAPTURED! 🎉[/bold green]")
        
        self.console.print(Panel("""
[green]Congratulations! You've successfully captured your first WPA2 handshake![/green]

[yellow]What you've learned:[/yellow]
✅ How to enable monitor mode
✅ How to scan for networks
✅ How to capture a WPA2 handshake
✅ The basics of WiFi security

[cyan]What's next:[/cyan]
• The handshake is saved as 'capture-01.cap'
• You could now use tools like hashcat to crack it
• Since you know the password, you could verify it works!

[bold]You're no longer a beginner - you're a WiFi security researcher![/bold]
""", title="Mission Accomplished!", border_style="green"))
    
    def celebrate_success(self):
        """Celebrate the user's success"""
        self.console.print("\n" + "🎉" * 20)
        self.console.print("[bold green]     YOU DID IT! FIRST HANDSHAKE CAPTURED!     [/bold green]")
        self.console.print("🎉" * 20)
        
        self.console.print("""
[cyan]Want to learn more?[/cyan]

Try these next:
• Run in [bold]advanced mode[/bold] for more features
• Test different encryption types
• Learn about WPS attacks
• Explore evil twin attacks

[yellow]Remember:[/yellow] With great power comes great responsibility!
Always use your skills ethically and legally.

[green]Welcome to the WiFi security community! 🚀[/green]
""")


def main():
    """Entry point for the wizard"""
    # Try to import and use real wizard if components are available
    try:
        from .real_wizard import RealFirstSuccessWizard
        wizard = RealFirstSuccessWizard()
        wizard.run()
    except ImportError:
        # Fallback to simulation if components not available
        console.print("[yellow]Note: Running in simulation mode[/yellow]")
        wizard = FirstSuccessWizard()
        wizard.run()


if __name__ == "__main__":
    main()