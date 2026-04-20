"""SPECTRE TUI — Evil Portal menu (dual-adapter only)."""

import json
from pathlib import Path

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error
from wifi_launchpad.providers.native.adapters.manager import AdapterManager

_settings = {
    "deauth": True,
    "whitelist_after_capture": True,
    "timeout": 300,
    "validate_psk": True,
    "dhcp_option_114": True,
}

# Submodule path (relative to package root)
_PORTALS_DIR = Path(__file__).resolve().parents[2] / "web" / "portals"


def evil_portal_menu():
    manager = AdapterManager()
    manager.discover_adapters()
    optimal = manager.get_optimal_setup()

    ap = optimal.get("ap")
    injection = optimal.get("injection")

    if not ap:
        divider("EVIL PORTAL")
        warn("Evil portal requires two wireless adapters.")
        console.print(
            "\n  [dim]Currently detected adapters:[/dim]"
        )
        for adapter in manager.adapters:
            console.print(
                f"  [dim]  {adapter.interface}: {adapter.chipset or 'Unknown'} "
                f"({adapter.assigned_role or 'no role'})[/dim]"
            )
        console.print(
            "\n  [dim]Add a second monitor-capable adapter to unlock evil portal.[/dim]\n"
            "  [dim]Evil portal uses one adapter as a rogue access point while[/dim]\n"
            "  [dim]the other performs deauthentication of the target network.[/dim]\n"
        )
        pause()
        return

    while True:
        divider("EVIL PORTAL")
        inj_iface = injection.interface if injection else "none"
        console.print(
            f"  [dim]AP: {ap.interface} ({ap.chipset}) | "
            f"Injection: {inj_iface}[/dim]\n"
        )
        console.print(
            "  [green][1][/green] Deploy portal\n"
            "  [green][2][/green] Browse templates\n"
            "  [green][3][/green] Active sessions\n"
            "  [green][4][/green] Stop portal\n"
            "  [green][5][/green] Settings\n"
            "  [green][6][/green] Back\n"
        )
        choice = prompt("spectre/portal")

        if choice == "1":
            _deploy_portal()
        elif choice == "2":
            _browse_templates()
        elif choice == "3":
            _active_sessions()
        elif choice == "4":
            _stop_portal()
        elif choice == "5":
            _portal_settings()
        elif choice == "6":
            return
        else:
            warn("Invalid choice.")


def _deploy_portal():
    info("Evil portal deployment is not yet implemented.")
    console.print(
        "  [dim]This feature requires the evil portal backend service.[/dim]\n"
        "  [dim]See: docs/development/specs/evil-portal-2026-04-15.md[/dim]\n"
    )
    pause()


def _browse_templates():
    """List available portal templates from manifest.json."""
    manifest_path = _PORTALS_DIR / "manifest.json"
    if not manifest_path.exists():
        warn("Portal templates not found.")
        console.print(
            "  [dim]Expected submodule at: web/portals/[/dim]\n"
            "  [dim]Run: git submodule add <evil-portals-url> "
            "src/wifi_launchpad/web/portals[/dim]\n"
        )
        pause()
        return

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        error(f"Failed to read manifest: {exc}")
        pause()
        return

    from rich.table import Table

    table = Table(title="Portal Templates", show_lines=False)
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category", style="green")
    table.add_column("Fields", style="yellow")
    table.add_column("SSID Patterns", style="dim")

    templates = manifest.get("templates", [])
    for tmpl in templates:
        table.add_row(
            tmpl.get("id", ""),
            tmpl.get("name", ""),
            tmpl.get("category", ""),
            ", ".join(tmpl.get("fields", [])),
            ", ".join(tmpl.get("ssid_patterns", [])),
        )

    console.print(table)
    console.print(f"\n  [dim]{len(templates)} templates available[/dim]\n")
    pause()


def _active_sessions():
    info("No portal currently running.")
    pause()


def _stop_portal():
    info("No portal currently running.")
    pause()


def _portal_settings():
    while True:
        deauth = "[green]ON[/green]" if _settings["deauth"] else "[red]OFF[/red]"
        whitelist = "[green]ON[/green]" if _settings["whitelist_after_capture"] else "[red]OFF[/red]"
        timeout = _settings["timeout"]
        psk = "[green]ON[/green]" if _settings["validate_psk"] else "[red]OFF[/red]"
        dhcp114 = "[green]ON[/green]" if _settings["dhcp_option_114"] else "[red]OFF[/red]"

        divider("EVIL PORTAL SETTINGS")
        console.print(
            f"  [green][1][/green] Deauth during portal   [{deauth}]\n"
            f"  [green][2][/green] Auto-whitelist capture  [{whitelist}]\n"
            f"  [green][3][/green] Portal timeout          [{timeout}s]\n"
            f"  [green][4][/green] PSK validation          [{psk}]\n"
            f"  [green][5][/green] DHCP Option 114         [{dhcp114}]\n"
            f"  [green][6][/green] Back\n"
        )
        choice = prompt("spectre/portal/settings")

        if choice == "1":
            _settings["deauth"] = not _settings["deauth"]
            from wifi_launchpad.cli.tui.helpers import success
            success(f"Deauth: {'ON' if _settings['deauth'] else 'OFF'}")
        elif choice == "2":
            _settings["whitelist_after_capture"] = not _settings["whitelist_after_capture"]
            from wifi_launchpad.cli.tui.helpers import success
            success(f"Auto-whitelist: {'ON' if _settings['whitelist_after_capture'] else 'OFF'}")
        elif choice == "3":
            val = prompt("Portal timeout seconds (60-1800) [300]")
            try:
                v = int(val)
                if 60 <= v <= 1800:
                    _settings["timeout"] = v
                    from wifi_launchpad.cli.tui.helpers import success
                    success(f"Timeout: {v}s")
                else:
                    warn("Value must be between 60 and 1800")
            except ValueError:
                warn("Enter a number")
        elif choice == "4":
            _settings["validate_psk"] = not _settings["validate_psk"]
            from wifi_launchpad.cli.tui.helpers import success
            success(f"PSK validation: {'ON' if _settings['validate_psk'] else 'OFF'}")
        elif choice == "5":
            _settings["dhcp_option_114"] = not _settings["dhcp_option_114"]
            from wifi_launchpad.cli.tui.helpers import success
            success(f"DHCP Option 114: {'ON' if _settings['dhcp_option_114'] else 'OFF'}")
        elif choice == "6":
            return
        else:
            warn("Invalid choice.")
