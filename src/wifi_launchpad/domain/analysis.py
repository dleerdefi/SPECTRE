"""Domain models for LLM-powered WiFi security analysis.

The analysis layer is optional — SPECTRE operates fully without it.
Analysis pattern adapted from METATRON (https://github.com/sooryathejas/METATRON)
Copyright (c) 2026 sooryathejas — MIT License.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class WifiVulnerability:
    """A WiFi security vulnerability identified by LLM analysis."""

    name: str
    severity: str  # critical / high / medium / low
    bssid: str
    ssid: str
    description: str
    attack: str  # recommended attack vector
    fix: str  # remediation advice

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "description": self.description,
            "attack": self.attack,
            "fix": self.fix,
        }


@dataclass
class AnalysisResult:
    """Complete output from an LLM analysis session."""

    vulnerabilities: List[WifiVulnerability] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    summary: str = ""
    full_response: str = ""
    full_transcript: str = ""
    scan_data: str = ""
    rounds: int = 0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_level": self.risk_level,
            "summary": self.summary,
            "rounds": self.rounds,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class AnalysisCorrection:
    """A correction applied to an LLM finding by an external reviewer."""

    vuln_name: str
    correction: str
    correction_type: str  # false_positive, severity_change, missing_vuln, confirmed
    corrected_by: str = "unknown"  # claude-code, manual, etc.
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "vuln_name": self.vuln_name,
            "correction": self.correction,
            "correction_type": self.correction_type,
            "corrected_by": self.corrected_by,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Parsers (pure functions on domain types) ─────────────────────────


def parse_vulnerabilities(response: str) -> List[WifiVulnerability]:
    """Extract ``WIFI_VULN:`` blocks from LLM output."""
    vulns: list[WifiVulnerability] = []
    lines = response.splitlines()
    i = 0

    while i < len(lines):
        line = re.sub(r"\*+", "", lines[i]).strip()
        if line.startswith("WIFI_VULN:"):
            vuln = {
                "name": "", "severity": "medium",
                "bssid": "", "ssid": "",
                "description": "", "attack": "", "fix": "",
            }
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("WIFI_VULN:"):
                    vuln["name"] = part.replace("WIFI_VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("BSSID:"):
                    vuln["bssid"] = part.replace("BSSID:", "").strip()
                elif part.startswith("SSID:"):
                    vuln["ssid"] = part.replace("SSID:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 5:
                nxt = re.sub(r"\*+", "", lines[j]).strip()
                if nxt.startswith(("WIFI_VULN:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if nxt.startswith("DESC:"):
                    vuln["description"] = nxt.replace("DESC:", "").strip()
                elif nxt.startswith("ATTACK:"):
                    vuln["attack"] = nxt.replace("ATTACK:", "").strip()
                elif nxt.startswith("FIX:"):
                    vuln["fix"] = nxt.replace("FIX:", "").strip()
                j += 1

            if vuln["name"]:
                vulns.append(WifiVulnerability(**vuln))
        i += 1

    return vulns


def parse_risk_level(response: str) -> str:
    """Extract ``RISK_LEVEL:`` from LLM response."""
    match = re.search(r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)", response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    """Extract ``SUMMARY:`` from LLM response."""
    match = re.search(r"SUMMARY:\s*(.+)", response, re.IGNORECASE)
    return match.group(1).strip() if match else ""
