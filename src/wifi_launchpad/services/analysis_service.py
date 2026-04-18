"""LLM-powered WiFi security analysis with agentic tool dispatch.

This service is **optional** — SPECTRE operates fully without it.
When the LLM backend is unavailable the ``analyze`` CLI command exits
gracefully with a message.

Inspired by METATRON's agentic analysis approach
(https://github.com/sooryathejas/METATRON).
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import List, Optional

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.analysis import (
    AnalysisResult,
    parse_recommendations,
    parse_risk_level,
    parse_summary,
    parse_vulnerabilities,
)
from wifi_launchpad.domain.survey import ScanResult
from wifi_launchpad.prompts import load_prompt
from wifi_launchpad.services.analysis_tools import AttackToolsMixin
from wifi_launchpad.services.llm_service import LLMService

logger = logging.getLogger(__name__)

_ALLOWED_TOOLS = {"survey", "capture", "crack", "nmap", "pixie", "reaver", "bully", "validate"}


class AnalysisService(AttackToolsMixin):
    """Orchestrates LLM analysis of WiFi survey data."""

    def __init__(self, llm: LLMService) -> None:
        self.llm = llm

    async def analyze(
        self,
        scan_results: ScanResult,
        max_rounds: Optional[int] = None,
        on_round: Optional[callable] = None,
        on_approval: Optional[callable] = None,
        auto_attack: bool = False,
    ) -> AnalysisResult:
        """Run the agentic analysis loop over scan data."""
        settings = get_settings()
        max_rounds = max_rounds or settings.llm.max_rounds
        scan_text = self.format_scan_data(scan_results)

        self._on_approval = on_approval  # callback for user approval of expensive ops

        system_prompt = load_prompt("analysis")
        if auto_attack:
            system_prompt += "\n" + load_prompt("auto_attack")

        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"WIFI SURVEY DATA:\n{scan_text}\n\n"
                    "Analyze these networks completely. Identify all "
                    "vulnerabilities, suggest attacks, and recommend fixes. "
                    "Use [TOOL:] or [SEARCH:] if you need more information."
                ),
            },
        ]

        final_response = ""
        all_responses: list[str] = []
        rounds = 0

        for loop in range(max_rounds):
            rounds = loop + 1
            response = await self.llm.ask(messages)

            if on_round:
                on_round(rounds, response)

            final_response = response
            all_responses.append(response)
            calls = self.llm.extract_tool_calls(response)
            if not calls:
                break

            tool_output = await self._dispatch_calls(calls)
            print(f"\n  [*] Sending tool results to AI for Round {rounds + 1}...")
            messages.append({"role": "assistant", "content": response})
            messages.append({
                "role": "user",
                "content": (
                    f"[TOOL RESULTS]\n{tool_output}\n\n"
                    "Continue your analysis with this new information. "
                    "If analysis is complete, give the final RISK_LEVEL and SUMMARY."
                ),
            })

        full_transcript = "\n\n".join(all_responses)

        # Parse from full_transcript — handles truncated final rounds by
        # finding the last RISK_LEVEL/SUMMARY across all rounds.
        return AnalysisResult(
            vulnerabilities=parse_vulnerabilities(full_transcript),
            recommendations=parse_recommendations(full_transcript),
            risk_level=parse_risk_level(full_transcript),
            summary=parse_summary(full_transcript),
            full_response=final_response,
            full_transcript=full_transcript,
            scan_data=scan_text,
            rounds=rounds,
        )

    # ── Scan data formatting ─────────────────────────────────────────

    @staticmethod
    def format_scan_data(results: ScanResult) -> str:
        """Convert a ``ScanResult`` into plain text for the LLM."""
        lines = [
            f"WIFI SURVEY RESULTS ({results.duration:.0f} second scan)",
            "=" * 50,
            f"Networks Found: {len(results.networks)}",
            f"Clients Detected: {len(results.clients)}",
            "",
        ]

        for i, net in enumerate(results.networks, 1):
            clients = results.get_associated_clients(net.bssid)
            lines.append(f"NETWORK {i}:")
            lines.append(f"  SSID: {net.ssid or '(hidden)'} | BSSID: {net.bssid}")
            lines.append(
                f"  Channel: {net.channel} | Signal: {net.signal_strength} dBm"
                f" | Band: {net.band.value if net.band else 'Unknown'}"
            )
            lines.append(
                f"  Encryption: {net.encryption.value}"
                f" | Cipher: {net.cipher or 'None'}"
                f" | Auth: {net.authentication or 'None'}"
            )
            lines.append(
                f"  WPS: {'Enabled' if net.wps_enabled else 'Disabled'}"
                f"{' (Locked)' if net.wps_locked else ''}"
                f" | Hidden: {'Yes' if net.hidden else 'No'}"
            )
            lines.append(f"  Connected Clients: {len(clients)}")
            if net.manufacturer:
                lines.append(f"  Manufacturer: {net.manufacturer}")
            lines.append("")

        for i, client in enumerate(results.clients, 1):
            lines.append(f"CLIENT {i}:")
            lines.append(
                f"  MAC: {client.mac_address}"
                f" | Associated: {client.associated_bssid or 'None'}"
            )
            if client.probed_ssids:
                lines.append(f"  Probed SSIDs: {', '.join(client.probed_ssids)}")
            if client.manufacturer:
                lines.append(f"  Manufacturer: {client.manufacturer}")
            lines.append("")

        return "\n".join(lines)

    # ── Tool dispatch ────────────────────────────────────────────────

    async def _dispatch_calls(self, calls: list) -> str:
        parts: list[str] = []
        for i, (call_type, command) in enumerate(calls, 1):
            print(f"\n  [DISPATCH {i}/{len(calls)}] {call_type}: {command}")
            logger.info("[DISPATCH] %s: %s", call_type, command)
            if call_type == "TOOL":
                output = await self._run_tool(command)
            elif call_type == "SEARCH":
                output = await self._run_search(command)
            else:
                output = f"[!] Unknown call type: {call_type}"

            compressed = await self.llm.summarize(output.strip())
            parts.append(f"[{call_type} RESULT: {command}]")
            parts.append("-" * 40)
            parts.append(compressed)
            parts.append("")
        return "\n".join(parts)

    async def _run_tool(self, command: str) -> str:
        parts = command.strip().split()
        if not parts:
            return "[!] Empty tool command."
        tool = parts[0].lower()
        if tool not in _ALLOWED_TOOLS:
            return f"[!] Tool not permitted: {tool}."
        handlers = {
            "survey": lambda: self._tool_survey(parts[1:]),
            "capture": lambda: self._tool_capture(parts[1:]),
            "crack": lambda: self._tool_crack(parts[1:]),
            "nmap": lambda: self._tool_subprocess(parts),
            "pixie": lambda: self._tool_pixie(parts[1:]),
            "reaver": lambda: self._tool_reaver(parts[1:]),
            "bully": lambda: self._tool_bully(parts[1:]),
            "validate": lambda: self._tool_validate(parts[1:]),
        }
        handler = handlers.get(tool)
        return await handler() if handler else f"[!] Unhandled tool: {tool}"

    async def _tool_survey(self, args: list) -> str:
        duration = int(args[0]) if args and args[0].isdigit() else 30
        try:
            from wifi_launchpad.services.scanner_service import ScannerService
            from wifi_launchpad.services.scanner_config import ScanConfig, ScanMode
            service = ScannerService()
            if not await service.initialize():
                return "[!] Failed to initialize scanner."
            config = ScanConfig(mode=ScanMode.DISCOVERY, duration=duration)
            if not await service.start_scan(config):
                return "[!] Failed to start scan."
            await asyncio.sleep(duration)
            results = await service.stop_scan()
            return self.format_scan_data(results)
        except Exception as exc:
            return f"[!] Survey failed: {exc}"

    async def _tool_capture(self, args: list) -> str:
        bssid, channel, i = None, None, 0
        while i < len(args):
            if args[i] == "--bssid" and i + 1 < len(args):
                bssid = args[i + 1]; i += 2
            elif args[i] == "--channel" and i + 1 < len(args):
                channel = int(args[i + 1]); i += 2
            else:
                i += 1
        if not bssid:
            return "[!] capture requires --bssid."
        try:
            from wifi_launchpad.services.capture_service import CaptureService
            print(f"    Attempting capture on {bssid} (this may take 30-60s)...")
            service = CaptureService()
            if not await service.initialize():
                return "[!] Capture failed: adapter not in monitor mode. Your syntax was correct — do NOT change formats. Try another target."
            print(f"    Capture running — waiting for handshake...")
            success, info = await service.targeted_capture(bssid=bssid, no_fallback=True)
            if success and info:
                return f"[+] Handshake captured: {info}"
            return f"[-] No handshake for {bssid}. Target may be out of range or have no clients. Your syntax was correct — do NOT retry with different formats. Try another target."
        except Exception as exc:
            return f"[!] Capture failed: {exc}. Your syntax was correct — do NOT change formats. Try another target."

    async def _tool_crack(self, args: list) -> str:
        hash_file, i = None, 0
        while i < len(args):
            if args[i] == "--file" and i + 1 < len(args):
                hash_file = args[i + 1]; i += 2
            else:
                i += 1
        if not hash_file:
            return "[!] crack requires --file <path>."
        from pathlib import Path
        if not Path(hash_file).exists():
            return f"[!] File not found: {hash_file}. No handshake captured — nothing to crack."
        if self._on_approval:
            if not self._on_approval(f"AI wants to crack {hash_file}. GPU-intensive. Approve?"):
                return f"[-] User declined. Handshake saved: {hash_file}"
        else:
            return f"[-] Handshake ready: {hash_file}. Crack via: spectre crack --file {hash_file}"
        try:
            from wifi_launchpad.services.crack_service import CrackService
            result = CrackService().crack_hash(hash_file)
            return f"[+] Password: {result.password}" if result.password else f"[-] {result.status}"
        except Exception as exc:
            return f"[!] Crack failed: {exc}"

    @staticmethod
    async def _tool_subprocess(parts: list) -> str:
        try:
            proc = await asyncio.to_thread(
                subprocess.run, parts, capture_output=True, text=True, timeout=120,
            )
            output = proc.stdout or ""
            if proc.stderr:
                output += f"\nSTDERR:\n{proc.stderr}"
            return output or "[!] No output."
        except subprocess.TimeoutExpired:
            return "[!] Command timed out."
        except Exception as exc:
            return f"[!] Subprocess error: {exc}"

    @staticmethod
    async def _run_search(query: str) -> str:
        try:
            from duckduckgo_search import DDGS
            results = await asyncio.to_thread(lambda: list(DDGS().text(query, max_results=5)))
            lines = []
            for r in results:
                lines.append(f"- {r.get('title', '')}")
                lines.append(f"  {r.get('body', '')}")
                lines.append("")
            return "\n".join(lines) if lines else "No search results."
        except ImportError:
            return "[!] duckduckgo_search not installed."
        except Exception as exc:
            return f"[!] Search failed: {exc}"
