"""
WiFi Launchpad Quickstart Module

The "First Success Engine" - Guides users from zero to their first 
successful WPA2 handshake capture in under 10 minutes.
"""

from .wizard import FirstSuccessWizard
from .preflight import PreFlightCheck

__all__ = ["FirstSuccessWizard", "PreFlightCheck"]