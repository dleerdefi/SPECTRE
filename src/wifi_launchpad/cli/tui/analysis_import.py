"""Import corrections from external LLM review (paste-based UX)."""

from __future__ import annotations

import re

from rich.console import Console

from wifi_launchpad.cli.tui.helpers import prompt, pause, info, warn, success

console = Console()


def _select_analysis() -> int | None:
    """Show recent analyses and let user pick which one to correct."""
    try:
        from wifi_launchpad.services.db import DatabaseService
        db = DatabaseService()
        if not db.connect():
            return None
        cur = db._conn.execute(
            "SELECT id, risk_level, rounds, created_at "
            "FROM analysis_results ORDER BY created_at DESC LIMIT 10"
        )
        rows = cur.fetchall()
        db.disconnect()
    except Exception:
        return None

    if not rows:
        info("No analyses in DB yet — corrections will be unlinked.")
        return None

    console.print("\n[bold]Recent analyses:[/bold]")
    for i, (aid, risk, rounds, ts) in enumerate(rows, 1):
        ts_str = ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") else str(ts)[:16]
        console.print(f"  [green][{i}][/green] #{aid} — {ts_str} — {risk} — {rounds} round(s)")
    console.print(f"  [green][{len(rows) + 1}][/green] Most recent (default)\n")

    choice = prompt(f"Which analysis? [{len(rows) + 1}]")
    if choice.isdigit() and 1 <= int(choice) <= len(rows):
        return rows[int(choice) - 1][0]
    return rows[0][0]  # default to most recent


def import_corrections():
    """Parse pasted external LLM review into structured corrections."""
    evaluator = prompt("Evaluator name (e.g., claude-opus-4-6)")
    if not evaluator:
        evaluator = "unknown"

    analysis_id = _select_analysis()

    console.print("\nPaste the external LLM's review below.")
    console.print("Type [bold]END[/bold] on its own line when done.\n")

    response_lines: list[str] = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        response_lines.append(line)

    text = "\n".join(response_lines)
    if not text.strip():
        warn("Empty response. Nothing imported.")
        return

    # Auto-detect analysis_id from pasted content
    aid_match = re.search(r"Analysis ID:\s*(\d+)", text, re.IGNORECASE)
    if aid_match and not analysis_id:
        analysis_id = int(aid_match.group(1))
        info(f"Auto-detected Analysis ID: {analysis_id}")

    # Parse EVAL: blocks (metatron-ai structured format)
    corrections: list[dict] = []
    blocks = re.split(r"(?=EVAL:)", text, flags=re.IGNORECASE)
    for block in blocks:
        block = block.strip()
        if not block.upper().startswith("EVAL:"):
            continue

        def _extract(pattern, src, default=""):
            m = re.search(pattern, src, re.IGNORECASE)
            return m.group(1).strip() if m else default

        vuln_name = _extract(r"EVAL:\s*(.+?)(?:\n|$)", block)
        verdict = _extract(r"VERDICT:\s*(.+?)(?:\n|$)", block, "unknown").lower()
        notes = _extract(
            r"NOTES:\s*(.+?)(?=\n(?:EVAL:|OVERALL_|HALLUCINATION_|ACCURACY_)|$)",
            block, "",
        )
        if vuln_name:
            corrections.append({
                "vuln": vuln_name,
                "type": verdict if verdict in (
                    "hallucination", "corrected", "verified", "downgraded", "reclassified",
                ) else None,
                "correction": notes,
            })

    # Fallback: legacy markdown format (### VULN- / CORRECTION:)
    if not corrections:
        current_vuln = None
        for line in text.splitlines():
            if line.startswith("### VULN-"):
                current_vuln = line.replace("### ", "").strip()
            elif line.startswith("- **CORRECTION**:") and current_vuln:
                val = line.split(":", 1)[1].strip()
                if val:
                    corrections.append({"vuln": current_vuln, "correction": val, "type": None})
            elif line.startswith("- **CORRECTION_TYPE**:") and corrections:
                val = line.split(":", 1)[1].strip()
                for valid in ("hallucination", "corrected", "verified", "downgraded", "reclassified"):
                    if valid in val:
                        corrections[-1]["type"] = valid
                        break

    if not corrections:
        warn("No corrections found. Expected EVAL: blocks or ### VULN- format.")
        return

    success(f"Found {len(corrections)} correction(s) from {evaluator}:")
    for c in corrections:
        console.print(f"  {c['vuln']}: [{c.get('type') or 'untyped'}] {c['correction'][:60]}")

    # Persist to DB
    saved = 0
    try:
        from wifi_launchpad.services.db import DatabaseService
        db = DatabaseService()
        if db.connect():
            for c in corrections:
                if db.save_correction(
                    analysis_id=analysis_id or 0,
                    vuln_name=c["vuln"],
                    correction_type=c.get("type") or "corrected",
                    correction=c.get("correction", ""),
                    corrected_by=evaluator,
                    original_finding=c["vuln"],
                ):
                    saved += 1
            db.disconnect()
    except Exception:
        pass

    if saved:
        success(f"Saved {saved} correction(s) to DB (analysis #{analysis_id})")
    else:
        info("Corrections displayed but not persisted (DB unavailable)")
    pause()
