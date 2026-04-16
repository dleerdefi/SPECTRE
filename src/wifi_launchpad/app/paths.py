"""Filesystem path helpers for the packaged runtime."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = PROJECT_ROOT / "src"
DOCS_ROOT = PROJECT_ROOT / "docs"
CONFIG_ROOT = PROJECT_ROOT / "config"
WORDLIST_ROOT = PROJECT_ROOT / "wordlists"
CASE_ROOT = PROJECT_ROOT / "cases"
CAPTURE_ROOT = PROJECT_ROOT / "captures"
LOG_ROOT = PROJECT_ROOT / "logs"
TEMP_ROOT = Path("/tmp/spectre")
