"""Native capture provider components.

Keep imports lazy so basic capture-service and compatibility shims do not
trigger Scapy initialization until validation is explicitly requested.
"""

__all__ = [
    "CaptureConfig",
    "CaptureManager",
    "CaptureStatus",
    "DeauthConfig",
    "DeauthController",
    "DeauthStrategy",
    "HandshakeType",
    "HandshakeValidator",
    "ValidationResult",
]


def __getattr__(name):
    """Lazily expose capture provider symbols."""

    if name in {"CaptureConfig", "CaptureStatus", "DeauthConfig", "DeauthStrategy", "HandshakeType", "ValidationResult"}:
        from .models import (
            CaptureConfig,
            CaptureStatus,
            DeauthConfig,
            DeauthStrategy,
            HandshakeType,
            ValidationResult,
        )

        return {
            "CaptureConfig": CaptureConfig,
            "CaptureStatus": CaptureStatus,
            "DeauthConfig": DeauthConfig,
            "DeauthStrategy": DeauthStrategy,
            "HandshakeType": HandshakeType,
            "ValidationResult": ValidationResult,
        }[name]

    if name == "CaptureManager":
        from .manager import CaptureManager

        return CaptureManager

    if name == "DeauthController":
        from .deauth import DeauthController

        return DeauthController

    if name == "HandshakeValidator":
        from .validation import HandshakeValidator

        return HandshakeValidator

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
