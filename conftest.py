#!/usr/bin/env python3
"""Pytest configuration for the packaged runtime."""

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
