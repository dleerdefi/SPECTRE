"""Case-store accessors for CLI and future API surfaces."""

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.storage.case_store import CaseStore


def get_case_store() -> CaseStore:
    """Return the default case store rooted in the configured case directory."""

    return CaseStore(get_settings().case_dir)
