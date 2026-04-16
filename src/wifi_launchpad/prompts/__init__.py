"""System prompts for LLM-powered analysis.

Prompts are stored as plain text files in this directory so operators
can review and customize them without editing Python code.
"""

from pathlib import Path

_PROMPT_DIR = Path(__file__).parent


def load_prompt(name: str) -> str:
    """Load a prompt file by name (without extension)."""
    path = _PROMPT_DIR / f"{name}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Prompt not found: {path}")
    return path.read_text(encoding="utf-8").strip()
