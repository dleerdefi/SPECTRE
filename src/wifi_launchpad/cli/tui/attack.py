"""SPECTRE TUI — Attack Campaign menu."""

import os

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn


def attack_menu():
    while True:
        divider("ATTACK CAMPAIGN")
        warn("Requires sudo and monitor-capable adapter")
        console.print(
            "\n  [green][1][/green] Full autopwn (survey → attack → crack)\n"
            "  [green][2][/green] Quick capture (survey → capture only)\n"
            "  [green][3][/green] Back\n"
        )
        choice = prompt("spectre/attack")

        if choice == "1":
            info("Launching autopwn...")
            console.print("[dim]  Tip: run from CLI for full control:[/dim]")
            console.print("[dim]  sudo $(which spectre) autopwn --scan-time 90 --crack[/dim]\n")

            st = prompt("Scan time in seconds [90]")
            scan_time = int(st) if st.isdigit() else 90

            try:
                os.system(
                    f"sudo $(which python3) -m wifi_launchpad autopwn "
                    f"--scan-time {scan_time} --crack"
                )
            except KeyboardInterrupt:
                warn("Campaign aborted.")
            pause()

        elif choice == "2":
            info("Launching quick capture...")
            try:
                os.system("sudo $(which python3) -m wifi_launchpad quickcapture")
            except KeyboardInterrupt:
                warn("Capture aborted.")
            pause()

        elif choice == "3":
            return
        else:
            warn("Invalid choice.")
