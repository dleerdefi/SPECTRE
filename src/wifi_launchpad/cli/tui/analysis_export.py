"""Export analysis results to markdown for external review."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from wifi_launchpad.cli.tui.helpers import success


def export_result(result, settings_dict):
    """Export analysis result to markdown for external review."""
    from wifi_launchpad.app.settings import get_settings

    app_settings = get_settings()
    export_dir = app_settings.project_root / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = export_dir / f"spectre_analysis_{ts}.md"

    analysis_id = settings_dict.get("last_analysis_id", "unknown")
    lines = [
        "# SPECTRE Analysis Export", "",
        "## Metadata",
        f"- Analysis ID: {analysis_id}",
        f"- Rounds: {result.rounds}",
        f"- Auto-attack: {'ON' if settings_dict.get('auto_attack') else 'OFF'}",
        f"- Timestamp: {result.timestamp.isoformat()}", "",
        "## Scan Data", "```", result.scan_data, "```", "",
        "## AI Analysis (Full Response)", "```", result.full_transcript or result.full_response, "```", "",
        "## Parsed Findings", "",
    ]
    for i, v in enumerate(result.vulnerabilities, 1):
        lines.extend([
            f"### VULN-{i}: {v.name}",
            f"- Severity: {v.severity.upper()}",
            f"- Confidence: {v.confidence}",
            f"- BSSID: {v.bssid}",
            f"- SSID: {v.ssid}",
            f"- Evidence: {v.evidence}",
            f"- Description: {v.description}",
            f"- Attack: {v.attack}",
            f"- Fix: {v.fix}",
            "- **CORRECTION**: ",
            "- **CORRECTION_TYPE**: [hallucination | corrected | verified | downgraded | reclassified]",
            "",
        ])
    if result.recommendations:
        lines.extend(["## Recommendations", ""])
        for r in result.recommendations:
            lines.extend([f"### REC: {r.name}", f"- {r.description}", ""])
    lines.extend([
        f"## Risk Level: {result.risk_level}",
        f"## Summary: {result.summary}", "",
        "## Reviewer Notes", "[leave blank for reviewer to fill in]", "",
    ])
    filename.write_text("\n".join(lines))
    success(f"Exported to {filename}")
