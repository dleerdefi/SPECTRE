"""Shared CLI helpers."""

import json
import os
from io import StringIO

import click
from rich.console import Console

console = Console()

_LOGO = """\
\033[91m
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
\033[0m"""


def _status_line() -> str:
    """Build a live status bar showing adapter, DB, and LLM state."""
    parts: list[str] = []

    # Adapter — show monitor-mode interface, or first available
    try:
        import subprocess
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=2,
        )
        lines = result.stdout.splitlines()
        monitor_iface, any_iface = None, None
        for i, line in enumerate(lines):
            if "Interface" in line:
                iface = line.split()[-1]
                if not any_iface:
                    any_iface = iface
                # Check if next lines mention monitor mode
                for j in range(i + 1, min(i + 5, len(lines))):
                    if "monitor" in lines[j].lower():
                        monitor_iface = iface
                        break
        if monitor_iface:
            parts.append(f"\033[92m■\033[0m Adapter: {monitor_iface} (monitor)")
        elif any_iface:
            parts.append(f"\033[93m■\033[0m Adapter: {any_iface} (managed)")
        else:
            parts.append("\033[90m□ No adapter\033[0m")
    except Exception:
        parts.append("\033[90m□ Adapter: ?\033[0m")

    # Database
    try:
        from wifi_launchpad.app.settings import get_settings
        cfg = get_settings().db
        if cfg.password:
            parts.append(f"\033[92m■\033[0m DB: {cfg.host}:{cfg.port}")
        else:
            parts.append("\033[90m□ DB: not configured\033[0m")
    except Exception:
        parts.append("\033[90m□ DB: ?\033[0m")

    # LLM
    try:
        from wifi_launchpad.app.settings import get_settings
        cfg = get_settings().llm
        parts.append(f"\033[92m■\033[0m LLM: {cfg.url}")
    except Exception:
        parts.append("\033[90m□ LLM: ?\033[0m")

    return "  " + "  |  ".join(parts)


def print_banner():
    """Clear screen and display the SPECTRE banner with live status."""
    os.system("clear")
    print(_LOGO)
    print(_status_line())
    print("\033[90m  ──────────────────────────────────────────────────────────\033[0m")


def emit_json(payload):
    """Render a machine-readable JSON payload."""

    click.echo(json.dumps(payload, indent=2))


def quiet_console():
    """Return a quiet rich console suitable for JSON-oriented code paths."""

    return Console(file=StringIO(), force_terminal=False, color_system=None)


def serialize_adapter(adapter):
    """Normalize adapter metadata for JSON output."""

    return {
        "interface": adapter.interface,
        "chipset": adapter.chipset,
        "driver": adapter.driver,
        "mode": adapter.current_mode,
        "bands": list(adapter.frequency_bands),
        "monitor_mode": adapter.monitor_mode,
        "packet_injection": adapter.packet_injection,
        "role": adapter.assigned_role,
    }
