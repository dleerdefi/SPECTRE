"""External provider integrations.

These integrations wrap battle-tested third-party tools and keep the package
focused on orchestration, evidence handling, and operator workflow glue.
"""

__all__ = ["EvilPortalProvider", "HCXCaptureProvider", "HashcatProvider", "KismetSurveyProvider"]


def __getattr__(name):
    """Lazily expose external provider integrations."""

    if name == "EvilPortalProvider":
        from .evil_portal import EvilPortalProvider

        return EvilPortalProvider

    if name == "HCXCaptureProvider":
        from .hcx import HCXCaptureProvider

        return HCXCaptureProvider

    if name == "HashcatProvider":
        from .hashcat import HashcatProvider

        return HashcatProvider

    if name == "KismetSurveyProvider":
        from .kismet import KismetSurveyProvider

        return KismetSurveyProvider

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
