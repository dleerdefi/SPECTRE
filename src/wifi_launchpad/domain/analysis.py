"""Domain models for LLM-powered WiFi security analysis.

The analysis layer is optional — SPECTRE operates fully without it.
Inspired by METATRON's agentic analysis approach
(https://github.com/sooryathejas/METATRON).
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
    confidence: str = "possible"  # confirmed / likely / possible
    evidence: str = ""  # quoted scan output supporting this finding
    bssid: str = ""
    ssid: str = ""
    description: str = ""
    attack: str = ""  # recommended attack vector
    fix: str = ""  # remediation advice

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "description": self.description,
            "attack": self.attack,
            "fix": self.fix,
        }


@dataclass
class WifiRecommendation:
    """A security hardening recommendation (not a vulnerability)."""

    name: str
    description: str

    def to_dict(self) -> dict:
        return {"name": self.name, "description": self.description}


@dataclass
class AnalysisResult:
    """Complete output from an LLM analysis session."""

    vulnerabilities: List[WifiVulnerability] = field(default_factory=list)
    recommendations: List[WifiRecommendation] = field(default_factory=list)
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
            "recommendations": [r.to_dict() for r in self.recommendations],
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
    correction_type: str  # hallucination, corrected, verified, downgraded, reclassified
    corrected_by: str = "unknown"  # claude-opus-4-6, manual, etc.
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

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
_TOOL_NOISE_REC = {"tool parameter", "capture service", "api parameter", "service restart"}


def _completeness(v: WifiVulnerability) -> int:
    """Count non-empty fields for dedup preference."""
    return sum(1 for f in (v.evidence, v.description, v.attack, v.fix) if f)


def parse_vulnerabilities(response: str) -> List[WifiVulnerability]:
    """Extract ``WIFI_VULN:`` blocks from LLM output."""
    vulns: list[WifiVulnerability] = []
    lines = response.splitlines()
    i = 0

    while i < len(lines):
        line = re.sub(r"\*+", "", lines[i]).strip()
        if line.startswith("WIFI_VULN:"):
            vuln = {
                "name": "", "severity": "medium", "confidence": "possible",
                "evidence": "", "bssid": "", "ssid": "",
                "description": "", "attack": "", "fix": "",
            }
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("WIFI_VULN:"):
                    vuln["name"] = part.replace("WIFI_VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("CONFIDENCE:"):
                    vuln["confidence"] = part.replace("CONFIDENCE:", "").strip().lower()
                elif part.startswith("BSSID:"):
                    vuln["bssid"] = part.replace("BSSID:", "").strip()
                elif part.startswith("SSID:"):
                    vuln["ssid"] = part.replace("SSID:", "").strip()

            # Validate confidence
            if vuln["confidence"] not in ("confirmed", "likely", "possible"):
                vuln["confidence"] = "possible"

            j = i + 1
            while j < len(lines) and j <= i + 6:
                nxt = re.sub(r"\*+", "", lines[j]).strip()
                if nxt.startswith(("WIFI_VULN:", "REC:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if nxt.startswith("EVIDENCE:"):
                    vuln["evidence"] = nxt.replace("EVIDENCE:", "").strip()
                elif nxt.startswith("DESC:"):
                    vuln["description"] = nxt.replace("DESC:", "").strip()
                elif nxt.startswith("ATTACK:"):
                    vuln["attack"] = nxt.replace("ATTACK:", "").strip()
                elif nxt.startswith("FIX:"):
                    vuln["fix"] = nxt.replace("FIX:", "").strip()
                j += 1

            if vuln["name"]:
                vulns.append(WifiVulnerability(**vuln))
        i += 1

    # Filter findings with non-MAC BSSIDs (tool-debugging noise like
    # "Global Session", "Multiple Targets", "N/A").
    vulns = [v for v in vulns if _MAC_RE.match(v.bssid)]

    # Deduplicate by (BSSID, name) — prefer the most complete version
    # (most non-empty fields). If tied, keep the later one (more context).
    seen: dict[tuple[str, str], WifiVulnerability] = {}
    for v in vulns:
        key = (v.bssid.upper(), v.name.lower())
        prev = seen.get(key)
        if prev is None or _completeness(v) >= _completeness(prev):
            seen[key] = v
    return list(seen.values())


def parse_recommendations(response: str) -> List[WifiRecommendation]:
    """Extract ``REC:`` blocks from LLM output."""
    recs: list[WifiRecommendation] = []
    lines = response.splitlines()
    i = 0

    while i < len(lines):
        line = re.sub(r"\*+", "", lines[i]).strip()
        if line.startswith("REC:"):
            name = line.replace("REC:", "").strip()
            description = ""

            j = i + 1
            while j < len(lines) and j <= i + 3:
                nxt = re.sub(r"\*+", "", lines[j]).strip()
                if nxt.startswith(("WIFI_VULN:", "REC:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if nxt.startswith("DESC:"):
                    description = nxt.replace("DESC:", "").strip()
                j += 1

            if name:
                recs.append(WifiRecommendation(name=name, description=description))
        i += 1

    # Filter tool-debugging noise (e.g., "Tool Parameter Configuration Update")
    recs = [r for r in recs if not any(kw in r.name.lower() for kw in _TOOL_NOISE_REC)]

    # Deduplicate by name
    seen: dict[str, WifiRecommendation] = {}
    for r in recs:
        seen[r.name.lower()] = r
    return list(seen.values())


def parse_risk_level(response: str) -> str:
    """Extract last ``RISK_LEVEL:`` from LLM response.

    Uses findall + last match so truncated final rounds don't lose
    the risk level that was emitted in an earlier complete round.
    """
    matches = re.findall(r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)", response, re.IGNORECASE)
    return matches[-1].upper() if matches else "UNKNOWN"


def parse_summary(response: str) -> str:
    """Extract last ``SUMMARY:`` from LLM response.

    Uses findall + last match for the same truncation-resilience
    reason as parse_risk_level.
    """
    matches = re.findall(r"SUMMARY:\s*(.+)", response, re.IGNORECASE)
    return matches[-1].strip() if matches else ""
