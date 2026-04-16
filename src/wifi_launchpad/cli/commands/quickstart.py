"""Beginner onboarding commands."""

import click
from rich.panel import Panel

from wifi_launchpad.cli.common import console
from wifi_launchpad.quickstart.screens import SANDBOX_DESCRIPTION


def register_quickstart_commands(cli):
    """Register quickstart commands."""

    @cli.command()
    def wizard():
        """Launch the First Success Wizard (beginner mode)."""

        from wifi_launchpad.quickstart.workflow import FirstSuccessWizard

        FirstSuccessWizard().run()

    @cli.command()
    def sandbox():
        """Launch sandbox mode (mobile hotspot tutorial)."""

        console.print(Panel(f"[bold cyan]Sandbox Mode[/bold cyan]\n\n{SANDBOX_DESCRIPTION}", border_style="cyan"))
        from rich.prompt import Confirm

        if Confirm.ask("\n[yellow]Ready to start sandbox mode?[/yellow]"):
            from wifi_launchpad.quickstart.workflow import FirstSuccessWizard

            wizard = FirstSuccessWizard()
            wizard.setup_mobile_hotspot()
            wizard.start_monitor_mode()
            wizard.scan_for_hotspot()
            wizard.capture_handshake()
            wizard.celebrate_success()
