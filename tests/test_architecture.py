#!/usr/bin/env python3
"""Architecture guardrails for the packaged runtime."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = ROOT / "src" / "wifi_launchpad"
FORBIDDEN_IMPORT_PATTERNS = [
    re.compile(r"^\s*from\s+core(\.|$)"),
    re.compile(r"^\s*import\s+core(\.|$)"),
    re.compile(r"^\s*from\s+quickstart(\.|$)"),
    re.compile(r"^\s*import\s+quickstart(\.|$)"),
    re.compile(r"^\s*from\s+services(\.|$)"),
    re.compile(r"^\s*import\s+services(\.|$)"),
]


class TestArchitectureGuardrails(unittest.TestCase):
    """Keep the packaged runtime isolated from legacy root modules."""

    def test_packaged_runtime_does_not_import_legacy_roots(self):
        violations = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if any(pattern.search(line) for pattern in FORBIDDEN_IMPORT_PATTERNS):
                    violations.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}")
        self.assertEqual(violations, [], "\n".join(violations))

    def test_packaged_modules_stay_under_soft_line_cap(self):
        violations = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            line_count = sum(1 for _ in path.open(encoding="utf-8"))
            if line_count > 325:
                violations.append(f"{path.relative_to(ROOT)}: {line_count} lines")
        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
