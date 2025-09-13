#!/usr/bin/env python3
"""
Pre-Flight Check System

Validates system readiness and automatically fixes common issues.
The most important feature for user retention - prevents failures before they happen.
"""

import subprocess
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class CheckResult:
    """Result of a pre-flight check"""
    name: str
    passed: bool
    message: str
    fix_command: Optional[str] = None
    fix_description: Optional[str] = None


@dataclass
class AdapterInfo:
    """Information about a WiFi adapter"""
    interface: str
    mac: str
    driver: str
    chipset: str
    usb_id: Optional[str] = None
    monitor_capable: bool = False
    injection_capable: bool = False
    recommended_role: Optional[str] = None


class PreFlightCheck:
    """Comprehensive pre-flight validation system"""
    
    # Known adapter mappings
    ADAPTER_DB = {
        "0bda:8812": {
            "name": "ALFA AWUS036ACH",
            "chipset": "RTL8812AU",
            "driver": "realtek-rtl88xxau-dkms",
            "driver_check": "88XXau|8812au",
            "recommended_role": "monitoring"
        },
        "0e8d:7961": {
            "name": "ALFA AWUS036AXML", 
            "chipset": "MT7921U",
            "driver": "mt7921u",
            "driver_check": "mt7921u",
            "recommended_role": "injection"
        },
        "148f:3070": {
            "name": "ALFA AWUS036NH",
            "chipset": "RT3070",
            "driver": "rt2800usb",
            "driver_check": "rt2800usb",
            "recommended_role": "legacy"
        },
        "0bda:8813": {
            "name": "ALFA AWUS1900",
            "chipset": "RTL8814AU",
            "driver": "realtek-rtl8814au-dkms",
            "driver_check": "8814au",
            "recommended_role": "high_power"
        }
    }
    
    def __init__(self):
        self.console = console
        self.results: List[CheckResult] = []
        self.adapters: List[AdapterInfo] = []
        self.fixes_available: List[CheckResult] = []
        
    def run_all_checks(self) -> bool:
        """Run all pre-flight checks"""
        self.console.print("\n[bold cyan]🔍 Running Pre-Flight Checks[/bold cyan]\n")
        
        checks = [
            ("Operating System", self.check_os),
            ("Required Tools", self.check_tools),
            ("WiFi Adapters", self.check_adapters),
            ("Monitor Mode Support", self.check_monitor_mode),
            ("Injection Support", self.check_injection),
            ("Driver Status", self.check_drivers),
            ("Permissions", self.check_permissions),
        ]
        
        all_passed = True
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            for name, check_func in checks:
                task = progress.add_task(f"Checking {name}...", total=1)
                
                result = check_func()
                self.results.append(result)
                
                progress.update(task, completed=1)
                
                if result.passed:
                    self.console.print(f"  ✅ {name}: [green]{result.message}[/green]")
                else:
                    self.console.print(f"  ❌ {name}: [red]{result.message}[/red]")
                    all_passed = False
                    
                    if result.fix_command:
                        self.fixes_available.append(result)
        
        return all_passed
    
    def check_os(self) -> CheckResult:
        """Check operating system compatibility"""
        if not sys.platform.startswith('linux'):
            return CheckResult(
                name="OS Check",
                passed=False,
                message="Not running on Linux",
                fix_description="WiFi Launchpad requires Linux (preferably Kali)"
            )
        
        # Check if Kali
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'Kali' in content:
                    return CheckResult(
                        name="OS Check",
                        passed=True,
                        message="Kali Linux detected - Perfect!"
                    )
                else:
                    return CheckResult(
                        name="OS Check",
                        passed=True,
                        message="Linux detected (non-Kali)"
                    )
        except:
            return CheckResult(
                name="OS Check",
                passed=True,
                message="Linux detected"
            )
    
    def check_tools(self) -> CheckResult:
        """Check for required tools"""
        required_tools = {
            'aircrack-ng': 'aircrack-ng',
            'airodump-ng': 'aircrack-ng',
            'aireplay-ng': 'aircrack-ng',
            'iwconfig': 'wireless-tools',
            'ifconfig': 'net-tools',
            'iw': 'iw'
        }
        
        missing_tools = []
        missing_packages = set()
        
        for tool, package in required_tools.items():
            try:
                subprocess.run(['which', tool], capture_output=True, check=True)
            except:
                missing_tools.append(tool)
                missing_packages.add(package)
        
        if missing_tools:
            packages = ' '.join(missing_packages)
            return CheckResult(
                name="Tools Check",
                passed=False,
                message=f"Missing tools: {', '.join(missing_tools)}",
                fix_command=f"sudo apt update && sudo apt install -y {packages}",
                fix_description="Install missing tools"
            )
        
        return CheckResult(
            name="Tools Check",
            passed=True,
            message="All required tools installed"
        )
    
    def check_adapters(self) -> CheckResult:
        """Detect WiFi adapters"""
        # Check USB adapters
        usb_adapters = self._detect_usb_adapters()
        
        # Check network interfaces
        interfaces = self._detect_interfaces()
        
        if not interfaces:
            return CheckResult(
                name="Adapter Check",
                passed=False,
                message="No WiFi adapters detected",
                fix_description="Please connect a WiFi adapter"
            )
        
        # Match USB devices with interfaces
        for interface in interfaces:
            adapter = AdapterInfo(
                interface=interface['name'],
                mac=interface.get('mac', 'unknown'),
                driver=interface.get('driver', 'unknown'),
                chipset='unknown'
            )
            
            # Try to match with USB device
            for usb in usb_adapters:
                if usb['id'] in self.ADAPTER_DB:
                    info = self.ADAPTER_DB[usb['id']]
                    adapter.chipset = info['chipset']
                    adapter.usb_id = usb['id']
                    adapter.recommended_role = info['recommended_role']
                    break
            
            self.adapters.append(adapter)
        
        adapter_count = len(self.adapters)
        if adapter_count >= 2:
            return CheckResult(
                name="Adapter Check",
                passed=True,
                message=f"Found {adapter_count} adapters - Dual adapter setup ready!"
            )
        elif adapter_count == 1:
            return CheckResult(
                name="Adapter Check",
                passed=True,
                message=f"Found 1 adapter - Basic setup possible"
            )
        else:
            return CheckResult(
                name="Adapter Check",
                passed=False,
                message="No suitable adapters found"
            )
    
    def _detect_usb_adapters(self) -> List[Dict]:
        """Detect USB WiFi adapters"""
        adapters = []
        try:
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                # Check for known WiFi vendors
                if any(vendor in line for vendor in ['Realtek', 'MediaTek', 'Ralink', 'Atheros']):
                    match = re.search(r'ID ([0-9a-f]{4}:[0-9a-f]{4})', line)
                    if match:
                        adapters.append({
                            'id': match.group(1),
                            'description': line
                        })
        except:
            pass
        
        return adapters
    
    def _detect_interfaces(self) -> List[Dict]:
        """Detect network interfaces"""
        interfaces = []
        try:
            # Get wireless interfaces
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            
            current_interface = {}
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {
                        'name': line.split('Interface')[1].strip()
                    }
                elif 'addr' in line and current_interface:
                    current_interface['mac'] = line.split('addr')[1].strip()
                elif 'type' in line and current_interface:
                    current_interface['type'] = line.split('type')[1].strip()
            
            if current_interface:
                interfaces.append(current_interface)
            
            # Get driver info
            for iface in interfaces:
                driver_path = Path(f"/sys/class/net/{iface['name']}/device/driver")
                if driver_path.exists():
                    iface['driver'] = driver_path.resolve().name
        except:
            pass
        
        return interfaces
    
    def check_monitor_mode(self) -> CheckResult:
        """Check monitor mode support"""
        capable_adapters = []
        
        for adapter in self.adapters:
            # Check if interface supports monitor mode
            try:
                result = subprocess.run(
                    ['iw', 'list'],
                    capture_output=True,
                    text=True
                )
                
                if 'monitor' in result.stdout.lower():
                    adapter.monitor_capable = True
                    capable_adapters.append(adapter.interface)
            except:
                pass
        
        if capable_adapters:
            return CheckResult(
                name="Monitor Mode",
                passed=True,
                message=f"Monitor mode available on: {', '.join(capable_adapters)}"
            )
        else:
            return CheckResult(
                name="Monitor Mode",
                passed=False,
                message="No adapters support monitor mode",
                fix_description="May need different adapter or driver"
            )
    
    def check_injection(self) -> CheckResult:
        """Check packet injection support"""
        # For now, assume injection works if monitor mode works
        # In production, would run actual injection test
        
        injection_capable = any(a.monitor_capable for a in self.adapters)
        
        if injection_capable:
            return CheckResult(
                name="Injection Support",
                passed=True,
                message="Packet injection should be available"
            )
        else:
            return CheckResult(
                name="Injection Support",
                passed=False,
                message="No injection-capable adapters found"
            )
    
    def check_drivers(self) -> CheckResult:
        """Check if proper drivers are loaded"""
        missing_drivers = []
        
        for adapter in self.adapters:
            if adapter.usb_id and adapter.usb_id in self.ADAPTER_DB:
                info = self.ADAPTER_DB[adapter.usb_id]
                driver_pattern = info['driver_check']
                
                # Check if driver is loaded
                try:
                    result = subprocess.run(['lsmod'], capture_output=True, text=True)
                    if not re.search(driver_pattern, result.stdout, re.IGNORECASE):
                        missing_drivers.append({
                            'adapter': info['name'],
                            'driver': info['driver']
                        })
                except:
                    pass
        
        if missing_drivers:
            drivers_str = ', '.join(d['driver'] for d in missing_drivers)
            return CheckResult(
                name="Driver Check",
                passed=False,
                message=f"Missing drivers: {drivers_str}",
                fix_command=f"sudo apt install -y {drivers_str}",
                fix_description="Install missing drivers"
            )
        
        return CheckResult(
            name="Driver Check",
            passed=True,
            message="All drivers loaded"
        )
    
    def check_permissions(self) -> CheckResult:
        """Check user permissions"""
        # Check if we can run sudo
        try:
            subprocess.run(['sudo', '-n', 'true'], capture_output=True, check=True)
            return CheckResult(
                name="Permissions",
                passed=True,
                message="Sudo access available"
            )
        except:
            return CheckResult(
                name="Permissions",
                passed=True,
                message="Will need sudo password for some operations"
            )
    
    def show_adapter_details(self):
        """Display detailed adapter information"""
        if not self.adapters:
            self.console.print("[yellow]No adapters detected[/yellow]")
            return
        
        table = Table(title="Detected WiFi Adapters", show_header=True, header_style="bold cyan")
        table.add_column("Interface", style="green")
        table.add_column("MAC Address", style="dim")
        table.add_column("Chipset", style="yellow")
        table.add_column("Driver")
        table.add_column("Monitor", style="cyan")
        table.add_column("Injection", style="cyan")
        table.add_column("Role", style="magenta")
        
        for adapter in self.adapters:
            table.add_row(
                adapter.interface,
                adapter.mac,
                adapter.chipset,
                adapter.driver,
                "✅" if adapter.monitor_capable else "❌",
                "✅" if adapter.injection_capable else "❌",
                adapter.recommended_role or "general"
            )
        
        self.console.print(table)
    
    def apply_fixes(self) -> bool:
        """Apply available fixes"""
        if not self.fixes_available:
            return True
        
        self.console.print("\n[yellow]Found issues that can be automatically fixed:[/yellow]")
        
        for fix in self.fixes_available:
            self.console.print(f"  • {fix.fix_description}")
        
        from rich.prompt import Confirm
        if Confirm.ask("\n[cyan]Apply fixes automatically?[/cyan]"):
            for fix in self.fixes_available:
                self.console.print(f"\n[cyan]Running: {fix.fix_command}[/cyan]")
                try:
                    subprocess.run(fix.fix_command, shell=True, check=True)
                    self.console.print(f"  ✅ Fixed: {fix.fix_description}")
                except Exception as e:
                    self.console.print(f"  ❌ Failed: {e}")
                    return False
        
        return True
    
    def get_summary(self) -> str:
        """Get summary of pre-flight check results"""
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        
        if passed == total:
            return f"[green]All {total} checks passed! System ready.[/green]"
        else:
            return f"[yellow]{passed}/{total} checks passed. Some issues need attention.[/yellow]"


def main():
    """Run pre-flight checks standalone"""
    checker = PreFlightCheck()
    
    console.print(Panel("""
[bold cyan]WiFi Launchpad Pre-Flight Check System[/bold cyan]

This tool validates your system is ready for WiFi penetration testing.
It will check for required tools, detect adapters, and fix common issues.
""", title="Pre-Flight Check", border_style="cyan"))
    
    all_passed = checker.run_all_checks()
    
    console.print(f"\n{checker.get_summary()}")
    
    if checker.adapters:
        console.print("\n")
        checker.show_adapter_details()
    
    if not all_passed and checker.fixes_available:
        checker.apply_fixes()
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())