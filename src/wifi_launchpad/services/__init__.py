"""Packaged service layer.

Keep imports lazy so lightweight commands such as ``--help`` and ``doctor`` do
not trigger scanner or capture dependencies at import time.
"""

__all__ = [
    "CaptureService",
    "CrackService",
    "PlatformService",
    "ProviderSpec",
    "ScanConfig",
    "ScanMode",
    "ScannerService",
    "ToolProbeSpec",
    "get_case_store",
]


def __getattr__(name):
    """Lazily expose packaged service symbols."""

    if name in {"PlatformService", "ProviderSpec", "ToolProbeSpec"}:
        from .doctor import PlatformService, ProviderSpec, ToolProbeSpec

        return {
            "PlatformService": PlatformService,
            "ProviderSpec": ProviderSpec,
            "ToolProbeSpec": ToolProbeSpec,
        }[name]

    if name == "get_case_store":
        from .cases import get_case_store

        return get_case_store

    if name == "CaptureService":
        from .capture_service import CaptureService

        return CaptureService

    if name == "CrackService":
        from .crack_service import CrackService

        return CrackService

    if name in {"ScannerService", "ScanConfig", "ScanMode"}:
        from .scanner_config import ScanConfig, ScanMode
        from .scanner_service import ScannerService

        return {
            "ScannerService": ScannerService,
            "ScanConfig": ScanConfig,
            "ScanMode": ScanMode,
        }[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
