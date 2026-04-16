#!/usr/bin/env python3
"""Quickstart packaging regression tests."""

import unittest

from wifi_launchpad.quickstart import FirstSuccessWizard
from wifi_launchpad.quickstart.preflight import PreFlightCheck


class TestQuickstartPackaging(unittest.TestCase):
    """Ensure quickstart exports resolve to the packaged runtime."""

    def test_quickstart_exports_live_under_packaged_namespace(self):
        self.assertTrue(FirstSuccessWizard.__module__.startswith("wifi_launchpad.quickstart"))
        self.assertTrue(PreFlightCheck.__module__.startswith("wifi_launchpad.quickstart"))


if __name__ == "__main__":
    unittest.main()
