"""SPECTRE TUI — System Check menu."""

import os

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, warn


def system_menu():
    while True:
        divider("SYSTEM CHECK")
        console.print(
            "  [green][1][/green] Doctor (full tool check)\n"
            "  [green][2][/green] Preflight\n"
            "  [green][3][/green] List adapters\n"
            "  [green][4][/green] Enable monitor mode\n"
            "  [green][5][/green] Connections (DB / LLM / SSH)\n"
            "  [green][6][/green] Back\n"
        )
        choice = prompt("spectre/system")

        if choice == "1":
            os.system("python3 -m wifi_launchpad doctor")
            pause()
        elif choice == "2":
            os.system("python3 -m wifi_launchpad preflight")
            pause()
        elif choice == "3":
            os.system("python3 -m wifi_launchpad adapters")
            pause()
        elif choice == "4":
            iface = prompt("Interface name")
            if iface:
                os.system(f"sudo python3 -m wifi_launchpad monitor --interface {iface}")
            pause()
        elif choice == "5":
            from wifi_launchpad.cli.tui.connections import connections_menu
            connections_menu()
        elif choice == "6":
            return
        else:
            warn("Invalid choice.")
