"""Packaged preflight validation service."""

from __future__ import annotations

import re
import subprocess
import sys
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .discovery import ADAPTER_DB, detect_interfaces, detect_usb_adapters, supports_monitor_mode
from .models import AdapterInfo, CheckResult

console = Console()


class PreFlightCheck:
    """Validate a local system before running the onboarding wizard."""

    def __init__(self) -> None:
        self.console = console
        self.results: List[CheckResult] = []
        self.adapters: List[AdapterInfo] = []
        self.fixes_available: List[CheckResult] = []

    def run_all_checks(self) -> bool:
        """Run the quickstart readiness suite."""

        self.console.print("\n[bold cyan]Running Pre-Flight Checks[/bold cyan]\n")
        self.results = []
        self.fixes_available = []
        self.adapters = []

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
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
            for label, check in checks:
                task = progress.add_task(f"Checking {label}...", total=1)
                result = check()
                self.results.append(result)
                progress.update(task, completed=1)

                if result.passed:
                    self.console.print(f"  ✅ {label}: [green]{result.message}[/green]")
                else:
                    self.console.print(f"  ❌ {label}: [red]{result.message}[/red]")
                    all_passed = False
                    if result.fix_command:
                        self.fixes_available.append(result)

        return all_passed

    def check_os(self) -> CheckResult:
        """Validate the runtime operating system."""

        if not sys.platform.startswith("linux"):
            return CheckResult("OS Check", False, "Not running on Linux", fix_description="SPECTRE requires Linux")

        try:
            content = open("/etc/os-release", "r", encoding="utf-8").read()
        except OSError:
            return CheckResult("OS Check", True, "Linux detected")

        if "Kali" in content:
            return CheckResult("OS Check", True, "Kali Linux detected - Perfect!")
        return CheckResult("OS Check", True, "Linux detected (non-Kali)")

    def check_tools(self) -> CheckResult:
        """Ensure the minimum toolchain is installed."""

        required_tools = {
            "aircrack-ng": "aircrack-ng",
            "airodump-ng": "aircrack-ng",
            "aireplay-ng": "aircrack-ng",
            "iwconfig": "wireless-tools",
            "ifconfig": "net-tools",
            "iw": "iw",
        }

        missing_tools = []
        missing_packages = set()
        for tool, package in required_tools.items():
            try:
                subprocess.run(["which", tool], capture_output=True, check=True)
            except (subprocess.CalledProcessError, OSError):
                missing_tools.append(tool)
                missing_packages.add(package)

        if missing_tools:
            packages = " ".join(sorted(missing_packages))
            return CheckResult(
                "Tools Check",
                False,
                f"Missing tools: {', '.join(missing_tools)}",
                fix_command=f"sudo apt update && sudo apt install -y {packages}",
                fix_description="Install missing tools",
            )

        return CheckResult("Tools Check", True, "All required tools installed")

    def check_adapters(self) -> CheckResult:
        """Detect and normalize locally available WiFi adapters."""

        usb_adapters = detect_usb_adapters()
        interfaces = detect_interfaces()
        if not interfaces:
            return CheckResult("Adapter Check", False, "No WiFi adapters detected", fix_description="Please connect a WiFi adapter")

        for interface in interfaces:
            adapter = AdapterInfo(
                interface=interface["name"],
                mac=interface.get("mac", "unknown"),
                driver=interface.get("driver", "unknown"),
                chipset="unknown",
            )
            for usb in usb_adapters:
                if usb["id"] not in ADAPTER_DB:
                    continue
                info = ADAPTER_DB[usb["id"]]
                adapter.chipset = info["chipset"]
                adapter.usb_id = usb["id"]
                adapter.recommended_role = info["recommended_role"]
                break
            self.adapters.append(adapter)

        count = len(self.adapters)
        if count >= 2:
            return CheckResult("Adapter Check", True, f"Found {count} adapters - Dual adapter setup ready!")
        if count == 1:
            return CheckResult("Adapter Check", True, "Found 1 adapter - Basic setup possible")
        return CheckResult("Adapter Check", False, "No suitable adapters found")

    def check_monitor_mode(self) -> CheckResult:
        """Check whether at least one adapter supports monitor mode."""

        if supports_monitor_mode():
            for adapter in self.adapters:
                adapter.monitor_capable = True
            names = ", ".join(adapter.interface for adapter in self.adapters) or "unknown"
            return CheckResult("Monitor Mode", True, f"Monitor mode available on: {names}")

        return CheckResult(
            "Monitor Mode",
            False,
            "No adapters support monitor mode",
            fix_description="May need different adapter or driver",
        )

    def check_injection(self) -> CheckResult:
        """Estimate packet injection readiness."""

        injection_capable = any(adapter.monitor_capable for adapter in self.adapters)
        for adapter in self.adapters:
            adapter.injection_capable = adapter.monitor_capable

        if injection_capable:
            return CheckResult("Injection Support", True, "Packet injection should be available")
        return CheckResult("Injection Support", False, "No injection-capable adapters found")

    def check_drivers(self) -> CheckResult:
        """Verify required adapter drivers appear to be loaded."""

        missing_drivers = []
        try:
            loaded_modules = subprocess.run(["lsmod"], capture_output=True, text=True, check=False).stdout
        except OSError:
            loaded_modules = ""

        for adapter in self.adapters:
            if not adapter.usb_id or adapter.usb_id not in ADAPTER_DB:
                continue
            info = ADAPTER_DB[adapter.usb_id]
            if not re.search(info["driver_check"], loaded_modules, re.IGNORECASE):
                missing_drivers.append(info["driver"])

        if missing_drivers:
            drivers = ", ".join(sorted(set(missing_drivers)))
            install_targets = " ".join(sorted(set(missing_drivers)))
            return CheckResult(
                "Driver Check",
                False,
                f"Missing drivers: {drivers}",
                fix_command=f"sudo apt install -y {install_targets}",
                fix_description="Install missing drivers",
            )

        return CheckResult("Driver Check", True, "All drivers loaded")

    def check_permissions(self) -> CheckResult:
        """Check whether passwordless sudo is already available."""

        try:
            subprocess.run(["sudo", "-n", "true"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, OSError):
            return CheckResult("Permissions", True, "Will need sudo password for some operations")
        return CheckResult("Permissions", True, "Sudo access available")

    def show_adapter_details(self) -> None:
        """Render a table of detected adapter details."""

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
                adapter.recommended_role or "general",
            )

        self.console.print(table)

    def apply_fixes(self) -> bool:
        """Apply shell-based fixes for detected issues."""

        if not self.fixes_available:
            return True

        from rich.prompt import Confirm

        self.console.print("\n[yellow]Found issues that can be automatically fixed:[/yellow]")
        for fix in self.fixes_available:
            self.console.print(f"  • {fix.fix_description}")

        if not Confirm.ask("\n[cyan]Apply fixes automatically?[/cyan]"):
            return True

        for fix in self.fixes_available:
            self.console.print(f"\n[cyan]Running: {fix.fix_command}[/cyan]")
            try:
                subprocess.run(fix.fix_command, shell=True, check=True)
            except Exception as exc:  # pragma: no cover - depends on local environment
                self.console.print(f"  ❌ Failed: {exc}")
                return False
            self.console.print(f"  ✅ Fixed: {fix.fix_description}")

        return True

    def get_summary(self) -> str:
        """Return a small rich-formatted readiness summary."""

        passed = sum(1 for result in self.results if result.passed)
        total = len(self.results)
        if passed == total:
            return f"[green]All {total} checks passed! System ready.[/green]"
        return f"[yellow]{passed}/{total} checks passed. Some issues need attention.[/yellow]"
