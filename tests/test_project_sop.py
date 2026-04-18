#!/usr/bin/env python3
"""Project-structure guardrails for the public packaged repo."""

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


class TestProjectSOP(unittest.TestCase):
    """Keep packaging and repository layout aligned with the packaged runtime."""

    @classmethod
    def setUpClass(cls):
        cls.data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))

    def test_packaging_only_targets_packaged_runtime(self):
        package_dir = self.data["tool"]["setuptools"]["package-dir"]
        packages = self.data["tool"]["setuptools"]["packages"]["find"]
        self.assertEqual(package_dir, {"": "src"})
        self.assertEqual(packages["where"], ["src"])
        self.assertEqual(packages["include"], ["wifi_launchpad*"])

    def test_pytest_is_anchored_on_tests_directory(self):
        pytest_config = self.data["tool"]["pytest"]["ini_options"]
        self.assertEqual(pytest_config["testpaths"], ["tests"])

    def test_repo_root_does_not_expose_legacy_runtime_surfaces(self):
        forbidden = [
            ROOT / "advanced",
            ROOT / "core",
            ROOT / "quickstart",
            ROOT / "services",
            ROOT / "src" / "config",
            ROOT / "src" / "preflight",
            ROOT / "requirements.txt",
        ]
        present = [str(path.relative_to(ROOT)) for path in forbidden if path.exists()]
        self.assertEqual(present, [], "\n".join(present))

    def test_manual_debug_scripts_are_not_part_of_the_public_repo(self):
        forbidden = sorted(
            [
                *(path.name for path in ROOT.glob("test_*.py")),
                *(path.name for path in ROOT.glob("debug_*.py")),
            ]
        )
        self.assertEqual(forbidden, [])

    def test_reference_docs_live_under_docs(self):
        required = [
            ROOT / ".env.example",
            ROOT / "docs" / "kismet-bug-fix.md",
        ]
        missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
        self.assertEqual(missing, [], "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
