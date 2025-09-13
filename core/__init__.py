"""
WiFi Launchpad Core Module

Core functionality for WiFi penetration testing.
"""

from .adapters import AdapterManager

# These will be implemented in future releases
# from .scanner import NetworkScanner
# from .capture import HandshakeCapture

__all__ = ["AdapterManager"]