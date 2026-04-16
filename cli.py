#!/usr/bin/env python3
"""Convenience entrypoint for the packaged CLI."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from wifi_launchpad.cli.main import cli, main  # noqa: E402

__all__ = ["cli", "main"]


if __name__ == "__main__":
    main()
