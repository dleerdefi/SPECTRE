"""Lightweight accessors for provider metadata."""

from wifi_launchpad.services.doctor import PlatformService, ProviderSpec, ToolProbeSpec


def get_provider_specs():
    """Return the current logical provider definitions."""

    return tuple(PlatformService.PROVIDER_SPECS)


def get_primary_provider_order():
    """Return the preferred provider order per role."""

    return dict(PlatformService.PRIMARY_PROVIDER_ORDER)


__all__ = ["ProviderSpec", "ToolProbeSpec", "get_primary_provider_order", "get_provider_specs"]
