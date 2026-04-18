"""Kismet data access — SQLite DB reader and REST API health checks."""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class KismetDbReader:
    """Read structured device data from a .kismet SQLite database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def read_devices(self) -> List[Dict[str, Any]]:
        """Return all 802.11 devices with their parsed JSON blobs."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT devmac, type, strongest_signal, first_time, last_time, device "
                "FROM devices WHERE phyname = 'IEEE802.11'"
            ).fetchall()
        finally:
            conn.close()

        devices: List[Dict[str, Any]] = []
        for row in rows:
            try:
                blob = json.loads(row["device"]) if row["device"] else {}
            except (json.JSONDecodeError, TypeError):
                blob = {}
            devices.append({
                "devmac": row["devmac"],
                "type": row["type"],
                "strongest_signal": row["strongest_signal"],
                "first_time": row["first_time"],
                "last_time": row["last_time"],
                "device": blob,
            })
        return devices

    def read_alerts(self) -> List[Dict[str, Any]]:
        """Return all alerts from the database."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT ts_sec, phyname, devmac, header, json FROM alerts"
            ).fetchall()
        finally:
            conn.close()

        alerts: List[Dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["json"]) if row["json"] else {}
            except (json.JSONDecodeError, TypeError):
                payload = {}
            alerts.append({
                "timestamp": row["ts_sec"],
                "phyname": row["phyname"],
                "devmac": row["devmac"],
                "header": row["header"],
                "detail": payload,
            })
        return alerts


class KismetRestClient:
    """Lightweight REST client for Kismet health checks during capture."""

    def __init__(
        self,
        base_url: str = "http://localhost:2501",
        auth: Tuple[str, str] = ("spectre", "spectre"),
    ) -> None:
        self.base_url = base_url.rstrip("/")
        creds = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        self._auth_header = f"Basic {creds}"

    def _get(self, path: str, timeout: int = 5) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        req = Request(url, headers={"Authorization": self._auth_header})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    def wait_for_ready(self, timeout: int = 15) -> bool:
        """Poll Kismet's status endpoint until it responds or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self._get("system/status.json", timeout=3)
                logger.debug("Kismet REST API is ready")
                return True
            except (URLError, OSError, ValueError):
                time.sleep(1)
        logger.warning("Kismet REST API did not become ready within %ds", timeout)
        return False

    def check_datasources(self) -> List[Dict[str, Any]]:
        """Return the list of active datasources."""
        try:
            return self._get("datasource/all_sources.json")
        except (URLError, OSError, ValueError) as exc:
            logger.warning("Failed to query Kismet datasources: %s", exc)
            return []


def find_kismet_db(log_dir: Path) -> Optional[Path]:
    """Find the most recent .kismet database in a directory."""
    candidates = sorted(log_dir.rglob("*.kismet"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


__all__ = ["KismetDbReader", "KismetRestClient", "find_kismet_db"]
