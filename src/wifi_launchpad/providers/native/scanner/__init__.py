"""Native scanner provider components.

Keep imports lazy so lightweight commands and compatibility shims do not pull
in scanner subprocess logic unless the caller actually needs it.
"""

__all__ = [
    "AirodumpParser",
    "ChannelStrategy",
    "IEParser",
    "NetworkScanner",
    "OUIDatabase",
    "get_device_type",
    "get_oui_database",
    "lookup_vendor",
]


def __getattr__(name):
    """Lazily expose scanner provider symbols."""

    if name == "AirodumpParser":
        from .airodump_parser import AirodumpParser

        return AirodumpParser

    if name in {"ChannelStrategy", "NetworkScanner"}:
        from .network_scanner import ChannelStrategy, NetworkScanner

        return {"ChannelStrategy": ChannelStrategy, "NetworkScanner": NetworkScanner}[name]

    if name == "IEParser":
        from .ie_parser import IEParser

        return IEParser

    if name in {"OUIDatabase", "get_device_type", "get_oui_database", "lookup_vendor"}:
        from .vendors import OUIDatabase, get_device_type, get_oui_database, lookup_vendor

        return {
            "OUIDatabase": OUIDatabase,
            "get_device_type": get_device_type,
            "get_oui_database": get_oui_database,
            "lookup_vendor": lookup_vendor,
        }[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

