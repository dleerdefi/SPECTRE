"""Learned rules persistence — LLM feedback loop.

Stores distilled rules from external LLM reviews (Claude, GPT, etc.) that get
injected into the analysis prompt on future scans. Small, relational data —
not a time-series hypertable.

Mixin usage: DatabaseService imports and reuses these methods. They expect
``self._conn`` from the parent class.
"""

from __future__ import annotations

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class LearnedRulesMixin:
    """Mix into DatabaseService to add wifi_learned_rules CRUD."""

    _conn = None  # type: ignore[assignment]  # provided by DatabaseService

    @property
    def connected(self) -> bool:  # pragma: no cover — overridden by parent
        return self._conn is not None and not self._conn.closed

    def save_learned_rule(self, rule_text: str, source: str) -> bool:
        """Insert a distilled rule from external LLM review."""
        if not self.connected:
            return False
        try:
            self._conn.execute(
                "INSERT INTO wifi_learned_rules (rule_text, source) VALUES (%s, %s)",
                (rule_text, source),
            )
            self._conn.commit()
            return True
        except Exception as exc:
            logger.debug("Learned rule insert failed: %s", exc)
            return False

    def get_learned_rules(self) -> List[Dict]:
        """Fetch all learned rules ordered by creation time."""
        if not self.connected:
            return []
        try:
            cur = self._conn.execute(
                "SELECT id, rule_text, source, created_at "
                "FROM wifi_learned_rules ORDER BY id"
            )
            return [
                {"id": r[0], "rule_text": r[1], "source": r[2], "created_at": r[3]}
                for r in cur.fetchall()
            ]
        except Exception as exc:
            logger.debug("Learned rules fetch failed: %s", exc)
            return []

    def clear_learned_rules(self) -> bool:
        """Remove all learned rules (used before importing a fresh distillation)."""
        if not self.connected:
            return False
        try:
            self._conn.execute("DELETE FROM wifi_learned_rules")
            self._conn.commit()
            return True
        except Exception as exc:
            logger.debug("Learned rules clear failed: %s", exc)
            return False
