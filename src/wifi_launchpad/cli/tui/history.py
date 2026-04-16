"""SPECTRE TUI — Browse History menu."""

import os

from rich.table import Table

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error


def history_menu():
    while True:
        divider("HISTORY")
        info("Querying database...")

        try:
            from wifi_launchpad.storage.case_store import CaseStore
            store = CaseStore()
            cases = store.list_cases()

            if cases:
                table = Table(title="Recorded Sessions", show_lines=True)
                table.add_column("ID", width=6)
                table.add_column("Name", width=25)
                table.add_column("Created", width=22)
                table.add_column("Status", width=12)

                for case in cases:
                    table.add_row(
                        str(case.get("id", "")), str(case.get("name", "")),
                        str(case.get("created_at", "")), str(case.get("status", "")),
                    )
                console.print(table)
            else:
                warn("No sessions found in database.")
        except Exception as exc:
            warn(f"Could not query database: {exc}")
            console.print("[dim]  Database may not be configured. Check DB_HOST env var.[/dim]")

        console.print(
            "\n  [green][1][/green] View case details (enter ID)\n"
            "  [green][2][/green] Back\n"
        )
        choice = prompt("spectre/history")

        if choice == "1":
            case_id = prompt("Case ID")
            if case_id:
                info(f"Viewing case {case_id}...")
                try:
                    os.system(f"python3 -m wifi_launchpad cases view {case_id}")
                except Exception:
                    error("Failed to view case.")
            pause()
        elif choice == "2":
            return
        else:
            warn("Invalid choice.")
            pause()
