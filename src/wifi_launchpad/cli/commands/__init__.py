"""CLI command registration helpers."""

from .analyze import register_analyze_commands
from .autopwn import register_autopwn_commands
from .capture import register_capture_commands
from .cases import register_case_commands
from .crack import register_crack_commands
from .quickstart import register_quickstart_commands
from .survey import register_survey_commands
from .system import register_system_commands
from .wordlists import register_wordlist_commands

__all__ = [
    "register_analyze_commands",
    "register_autopwn_commands",
    "register_capture_commands",
    "register_case_commands",
    "register_crack_commands",
    "register_quickstart_commands",
    "register_survey_commands",
    "register_system_commands",
    "register_wordlist_commands",
]
