"""
Network Scanner Module

Provides network discovery and monitoring capabilities using airodump-ng.
"""

from .models import (
    Network,
    Client,
    Handshake,
    ScanResult,
    EncryptionType,
    WiFiBand
)
from .parser import AirodumpParser
from .network_scanner import NetworkScanner, ChannelStrategy

__all__ = [
    # Models
    "Network",
    "Client",
    "Handshake",
    "ScanResult",
    "EncryptionType",
    "WiFiBand",
    # Parser
    "AirodumpParser",
    # Scanner
    "NetworkScanner",
    "ChannelStrategy"
]