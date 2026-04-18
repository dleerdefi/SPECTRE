"""Analysis persistence — save LLM results + corrections to PostgreSQL.

Stores analysis results, parsed vulnerabilities, and external review
corrections. All methods are best-effort (never crash on DB failure).

Mixin usage: DatabaseService imports and reuses these methods. They expect
``self._conn`` and ``self.connected`` from the parent class.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnalysisMixin:
    """Mix into DatabaseService to add analysis_* table CRUD."""

    _conn = None  # type: ignore[assignment]  # provided by DatabaseService

    @property
    def connected(self) -> bool:  # pragma: no cover — overridden by parent
        return self._conn is not None and not self._conn.closed

    def save_analysis(self, result) -> Optional[int]:
        """Save an AnalysisResult and its vulnerabilities. Returns analysis_id."""
        if not self.connected:
            return None

        try:
            from wifi_launchpad.app.settings import get_settings
            model_name = get_settings().llm.model or "unknown"

            cur = self._conn.execute(
                """
                INSERT INTO analysis_results (
                    scan_data, full_response, full_transcript,
                    risk_level, summary, model_name, rounds, auto_attack
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    result.scan_data,
                    result.full_response,
                    result.full_transcript,
                    result.risk_level,
                    result.summary,
                    model_name,
                    result.rounds,
                    False,
                ),
            )
            analysis_id = cur.fetchone()[0]

            for v in result.vulnerabilities:
                self._conn.execute(
                    """
                    INSERT INTO analysis_vulnerabilities (
                        analysis_id, name, severity, confidence, evidence,
                        bssid, ssid, description, attack, fix
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        analysis_id, v.name, v.severity,
                        getattr(v, "confidence", "possible"),
                        getattr(v, "evidence", ""),
                        v.bssid, v.ssid, v.description, v.attack, v.fix,
                    ),
                )

            self._conn.commit()
            logger.info(
                "Saved analysis #%d (%d vulns) to DB",
                analysis_id, len(result.vulnerabilities),
            )
            return analysis_id

        except Exception as exc:
            logger.debug("Analysis save failed: %s", exc)
            return None

    def save_correction(
        self,
        analysis_id: int,
        vuln_name: str,
        correction_type: str,
        correction: str,
        corrected_by: str = "unknown",
        original_finding: str = "",
        vuln_id: Optional[int] = None,
    ) -> bool:
        """Save a correction record linked to an analysis."""
        if not self.connected:
            return False

        try:
            self._conn.execute(
                """
                INSERT INTO analysis_corrections (
                    analysis_id, vuln_id, original_finding,
                    correction, corrected_by, correction_type
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    analysis_id, vuln_id, original_finding,
                    correction, corrected_by, correction_type,
                ),
            )
            self._conn.commit()
            return True
        except Exception as exc:
            logger.debug("Correction save failed: %s", exc)
            return False

    def get_corrections(self, analysis_id: Optional[int] = None) -> List[Dict]:
        """Fetch corrections, optionally filtered by analysis_id."""
        if not self.connected:
            return []
        try:
            if analysis_id:
                cur = self._conn.execute(
                    "SELECT id, analysis_id, vuln_id, original_finding, "
                    "correction, corrected_by, correction_type, created_at "
                    "FROM analysis_corrections WHERE analysis_id = %s "
                    "ORDER BY created_at",
                    (analysis_id,),
                )
            else:
                cur = self._conn.execute(
                    "SELECT id, analysis_id, vuln_id, original_finding, "
                    "correction, corrected_by, correction_type, created_at "
                    "FROM analysis_corrections ORDER BY created_at"
                )
            return [
                {
                    "id": r[0], "analysis_id": r[1], "vuln_id": r[2],
                    "original_finding": r[3], "correction": r[4],
                    "corrected_by": r[5], "correction_type": r[6],
                    "created_at": r[7],
                }
                for r in cur.fetchall()
            ]
        except Exception as exc:
            logger.debug("Corrections fetch failed: %s", exc)
            return []
