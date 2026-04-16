"""Quickstart preflight data models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class CheckResult:
    """Result of a single preflight validation step."""

    name: str
    passed: bool
    message: str
    fix_command: Optional[str] = None
    fix_description: Optional[str] = None


@dataclass
class AdapterInfo:
    """Basic WiFi adapter metadata used by the quickstart flow."""

    interface: str
    mac: str
    driver: str
    chipset: str
    usb_id: Optional[str] = None
    monitor_capable: bool = False
    injection_capable: bool = False
    recommended_role: Optional[str] = None

