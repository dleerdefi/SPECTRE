"""SPECTRE TUI — Attack Campaign menu."""

import os

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, success

_settings = {
    "scan_time": 90,
    "provider": "auto",
    "min_signal": -70,
    "attack_timeout": 120,
    "crack": True,
}


def attack_menu():
    while True:
        divider("ATTACK CAMPAIGN")
        warn("Requires sudo and monitor-capable adapter")
        prov = _settings["provider"]
        sig = _settings["min_signal"]
        timeout = _settings["attack_timeout"]
        crack = "[green]ON[/green]" if _settings["crack"] else "[red]OFF[/red]"

        # Check if AP adapter is available for evil portal
        from wifi_launchpad.providers.native.adapters.manager import AdapterManager
        _mgr = AdapterManager()
        _mgr.discover_adapters()
        _has_ap = _mgr.ap_adapter is not None

        if _has_ap:
            portal_line = "  [green][3][/green] Evil portal campaign\n"
        else:
            portal_line = "  [dim][3] Evil portal (requires 2nd adapter)[/dim]\n"

        console.print(
            f"\n  [green][1][/green] Full autopwn (survey → attack → crack)\n"
            f"  [green][2][/green] Quick capture (survey → capture only)\n"
            f"{portal_line}"
            f"  [green][4][/green] Settings\n"
            f"  [green][5][/green] Back\n"
            f"\n  [dim]Provider: {prov} | Signal: {sig} dBm | "
            f"Timeout: {timeout}s | Crack: {crack}[/dim]\n"
            f"  [dim]Adapters: {'Split mode (' + _mgr.injection_adapter.interface + ' monitor + ' + _mgr.ap_adapter.interface + ' injection)' if _has_ap else _mgr.injection_adapter.interface + ' (shared monitor/injection)' if _mgr.injection_adapter else 'none detected'}[/dim]\n"
        )
        choice = prompt("spectre/attack")

        if choice == "1":
            _run_autopwn()
        elif choice == "2":
            _run_quickcapture()
        elif choice == "3":
            if _has_ap:
                from wifi_launchpad.cli.tui.evil_portal import evil_portal_menu
                evil_portal_menu()
            else:
                warn("Evil portal requires two wireless adapters.")
                info("Add a second monitor-capable adapter to unlock this feature.")
        elif choice == "4":
            _attack_settings()
        elif choice == "5":
            return
        else:
            warn("Invalid choice.")


def _run_autopwn():
    info("Launching autopwn...")
    console.print("[dim]  Tip: run from CLI for full control:[/dim]")
    console.print("[dim]  sudo $(which spectre) autopwn --help[/dim]\n")

    st = prompt(f"Scan time in seconds [{_settings['scan_time']}]")
    scan_time = int(st) if st.isdigit() else _settings["scan_time"]

    crack_flag = "--crack" if _settings["crack"] else "--no-crack"
    try:
        os.system(
            f"sudo $(which python3) -m wifi_launchpad autopwn "
            f"--scan-time {scan_time} "
            f"--provider {_settings['provider']} "
            f"--min-signal {_settings['min_signal']} "
            f"--attack-timeout {_settings['attack_timeout']} "
            f"{crack_flag}"
        )
    except KeyboardInterrupt:
        warn("Campaign aborted.")
    pause()


def _run_quickcapture():
    info("Launching quick capture...")
    try:
        os.system("sudo $(which python3) -m wifi_launchpad quickcapture")
    except KeyboardInterrupt:
        warn("Capture aborted.")
    pause()


def _attack_settings():
    while True:
        prov = _settings["provider"]
        sig = _settings["min_signal"]
        timeout = _settings["attack_timeout"]
        crack = "ON" if _settings["crack"] else "OFF"

        divider("ATTACK SETTINGS")
        console.print(
            f"  [green][1][/green] Survey provider     [{prov}]\n"
            f"  [green][2][/green] Min signal strength [{sig} dBm]\n"
            f"  [green][3][/green] Attack timeout      [{timeout}s]\n"
            f"  [green][4][/green] Auto-crack          [{crack}]\n"
            f"  [green][5][/green] Back\n"
        )
        choice = prompt("spectre/attack/settings")

        if choice == "1":
            val = prompt("Provider (auto/kismet/native) [auto]")
            if val in ("auto", "kismet", "native"):
                _settings["provider"] = val
                success(f"Provider: {val}")
        elif choice == "2":
            val = prompt("Min signal dBm (-50 to -90) [-70]")
            try:
                v = int(val)
                if -90 <= v <= -30:
                    _settings["min_signal"] = v
                    success(f"Min signal: {v} dBm")
                else:
                    warn("Value must be between -90 and -30")
            except ValueError:
                warn("Enter a number")
        elif choice == "3":
            val = prompt("Attack timeout seconds (30-600) [120]")
            try:
                v = int(val)
                if 30 <= v <= 600:
                    _settings["attack_timeout"] = v
                    success(f"Attack timeout: {v}s")
                else:
                    warn("Value must be between 30 and 600")
            except ValueError:
                warn("Enter a number")
        elif choice == "4":
            _settings["crack"] = not _settings["crack"]
            success(f"Auto-crack: {'ON' if _settings['crack'] else 'OFF'}")
        elif choice == "5":
            return
        else:
            warn("Invalid choice.")
