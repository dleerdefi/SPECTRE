"""SPECTRE TUI — Cases & Reports menu."""

import os

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, error, warn


def case_menu():
    while True:
        divider("CASES & REPORTS")
        console.print(
            "  [green][1][/green] List cases\n"
            "  [green][2][/green] Create new case\n"
            "  [green][3][/green] Generate report\n"
            "  [green][4][/green] Back\n"
        )
        choice = prompt("spectre/cases")

        if choice == "1":
            try:
                os.system("python3 -m wifi_launchpad cases list")
            except Exception:
                error("Failed to list cases.")
            pause()
        elif choice == "2":
            name = prompt("Case name")
            if name:
                try:
                    os.system(f'python3 -m wifi_launchpad cases create --name "{name}"')
                except Exception:
                    error("Failed to create case.")
            pause()
        elif choice == "3":
            case_id = prompt("Case ID for report")
            if case_id:
                try:
                    os.system(f"python3 -m wifi_launchpad report --case-id {case_id}")
                except Exception:
                    error("Failed to generate report.")
            pause()
        elif choice == "4":
            return
        else:
            warn("Invalid choice.")
