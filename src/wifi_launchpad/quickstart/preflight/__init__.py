"""Packaged quickstart preflight exports."""

from .checks import PreFlightCheck
from .models import AdapterInfo, CheckResult
from .render import serialize_preflight

__all__ = ["AdapterInfo", "CheckResult", "PreFlightCheck", "serialize_preflight"]
