"""Shared CLI helpers."""

import json
import os
from io import StringIO

import click
from rich.console import Console

console = Console()

SPECTRE_BANNER = """\
\033[91m
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
\033[0m\
\033[90m  Wireless Tactical Assessment  |  Kali Linux
  ──────────────────────────────────────────────────────────\033[0m
"""


def print_banner():
    """Clear screen and display the SPECTRE banner."""
    os.system("clear")
    print(SPECTRE_BANNER)


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
