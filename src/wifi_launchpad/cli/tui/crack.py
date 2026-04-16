"""SPECTRE TUI — Crack Hashes menu."""

import os
from pathlib import Path

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error, success

_profiles = {
    "a": {"label": "CPU only",   "flags": ["--force", "-D", "1", "-w", "1"]},
    "b": {"label": "Single GPU", "flags": ["-D", "2", "-w", "3"]},
    "c": {"label": "Multi-GPU",  "flags": ["-D", "2", "-w", "4", "--opencl-device-types", "1,2"]},
}
_current = "b"


def crack_menu():
    global _current

    while True:
        divider("CRACK HASHES")
        prof = _profiles[_current]["label"]
        console.print(
            f"  [green][1][/green] Crack specific hash file\n"
            f"  [green][2][/green] Auto-crack all in capture dir\n"
            f"  [green][3][/green] Hardware profile  [dim]({prof})[/dim]\n"
            f"  [green][4][/green] Back\n"
        )
        choice = prompt("spectre/crack")

        if choice == "1":
            path = prompt("Path to .22000 hash file")
            if path and Path(path).exists():
                _run_crack(path)
            else:
                error(f"File not found: {path}")
        elif choice == "2":
            info("Auto-cracking all .22000 files...")
            try:
                os.system("python3 -m wifi_launchpad crack --auto")
            except KeyboardInterrupt:
                warn("Crack aborted.")
            pause()
        elif choice == "3":
            _profile_menu()
        elif choice == "4":
            return
        else:
            warn("Invalid choice.")


def _run_crack(hash_file: str):
    prof = _profiles[_current]["label"]
    info(f"Cracking with profile: {prof}")

    from wifi_launchpad.services.crack_service import CrackService
    service = CrackService()

    try:
        result = service.crack_hash(hash_file)
        if result.password:
            success(f"Password found: {result.password}")
        else:
            warn(f"Crack finished. Status: {result.status}")
    except Exception as exc:
        error(f"Crack failed: {exc}")
    pause()


def _profile_menu():
    global _current

    divider("HARDWARE PROFILES")
    console.print(
        "  [green][a][/green] CPU only       [dim](--force -D 1 -w 1)[/dim]\n"
        "  [green][b][/green] Single GPU     [dim](-D 2 -w 3)[/dim]\n"
        "  [green][c][/green] Multi-GPU      [dim](-D 2 -w 4)[/dim]\n"
        "  [green][d][/green] Custom\n"
    )
    choice = prompt("Profile").lower()
    if choice in ("a", "b", "c"):
        _current = choice
        success(f"Profile set: {_profiles[choice]['label']}")
    elif choice == "d":
        device = prompt("Device type (-D) [2]") or "2"
        workload = prompt("Workload (-w) [3]") or "3"
        _profiles["d"] = {"label": "Custom", "flags": ["-D", device, "-w", workload]}
        _current = "d"
        success("Custom profile saved.")
    else:
        warn("Invalid profile.")
