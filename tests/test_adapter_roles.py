#!/usr/bin/env python3
"""
Unit tests for adapter role assignment.

Verifies that AdapterManager correctly assigns roles for single-adapter
(backward compatible) and dual-adapter (evil portal ready) configurations.
"""

import unittest
from unittest.mock import patch

from wifi_launchpad.providers.native.adapters.models import WifiAdapter
from wifi_launchpad.providers.native.adapters.manager import AdapterManager


def _make_adapter(interface, chipset, driver, monitor=True, injection=True, bands=None):
    """Create a WifiAdapter with typical RTL8812AU or QCA9xxx properties."""
    adapter = WifiAdapter(
        interface=interface,
        mac_address=f"00:11:22:33:44:{interface[-1:].zfill(2)}",
        phy=f"phy{interface[-1:]}",
        driver=driver,
        chipset=chipset,
        monitor_mode=monitor,
        packet_injection=injection,
        frequency_bands=bands or ["2.4GHz", "5GHz"],
        current_mode="managed",
    )
    return adapter


class TestSingleAdapterRoles(unittest.TestCase):
    """Backward compatibility: single RTL8812AU setups must work unchanged."""

    def test_single_rtl8812au_with_management(self):
        """One RTL8812AU + one QCA9xxx: standard setup."""
        rtl = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)

        manager = AdapterManager()
        manager.adapters = [rtl, qca]
        manager._assign_roles()

        self.assertEqual(manager.injection_adapter, rtl)
        self.assertEqual(manager.monitor_adapter, rtl)
        self.assertIsNone(manager.ap_adapter)
        self.assertEqual(manager.management_adapter, qca)
        self.assertEqual(rtl.assigned_role, "injection")
        self.assertEqual(qca.assigned_role, "management")

    def test_single_rtl8812au_only(self):
        """One RTL8812AU, no other adapters."""
        rtl = _make_adapter("wlan0", "RTL8812AU", "88XXau")

        manager = AdapterManager()
        manager.adapters = [rtl]
        manager._assign_roles()

        self.assertEqual(manager.injection_adapter, rtl)
        self.assertEqual(manager.monitor_adapter, rtl)
        self.assertIsNone(manager.ap_adapter)
        self.assertIsNone(manager.management_adapter)


class TestDualAdapterRoles(unittest.TestCase):
    """Dual RTL8812AU setups: second adapter gets AP role."""

    def test_dual_rtl8812au_with_management(self):
        """Two RTL8812AU + one QCA9xxx: full tri-adapter config."""
        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)
        rtl2 = _make_adapter("wlan2", "RTL8812AU", "88XXau")

        manager = AdapterManager()
        manager.adapters = [rtl1, qca, rtl2]
        manager._assign_roles()

        self.assertEqual(manager.injection_adapter, rtl1)
        self.assertEqual(manager.monitor_adapter, rtl1)
        self.assertEqual(manager.ap_adapter, rtl2)
        self.assertEqual(manager.management_adapter, qca)
        self.assertEqual(rtl1.assigned_role, "injection")
        self.assertEqual(rtl2.assigned_role, "ap")
        self.assertEqual(qca.assigned_role, "management")

    def test_dual_rtl8812au_only(self):
        """Two RTL8812AU, no management adapter."""
        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        rtl2 = _make_adapter("wlan2", "RTL8812AU", "88XXau")

        manager = AdapterManager()
        manager.adapters = [rtl1, rtl2]
        manager._assign_roles()

        self.assertEqual(manager.injection_adapter, rtl1)
        self.assertEqual(manager.monitor_adapter, rtl1)
        self.assertEqual(manager.ap_adapter, rtl2)
        self.assertIsNone(manager.management_adapter)
        self.assertEqual(rtl1.assigned_role, "injection")
        self.assertEqual(rtl2.assigned_role, "ap")


class TestOptimalSetup(unittest.TestCase):
    """get_optimal_setup() always includes the 'ap' key."""

    def test_optimal_setup_single_adapter(self):
        rtl = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        manager = AdapterManager()
        manager.adapters = [rtl]
        manager._assign_roles()

        setup = manager.get_optimal_setup()
        self.assertIn("ap", setup)
        self.assertIsNone(setup["ap"])
        self.assertEqual(setup["injection"], rtl)

    def test_optimal_setup_dual_adapter(self):
        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        rtl2 = _make_adapter("wlan2", "RTL8812AU", "88XXau")
        manager = AdapterManager()
        manager.adapters = [rtl1, rtl2]
        manager._assign_roles()

        setup = manager.get_optimal_setup()
        self.assertEqual(setup["ap"], rtl2)
        self.assertEqual(setup["injection"], rtl1)


class TestSummary(unittest.TestCase):
    """summary() reflects adapter configuration correctly."""

    def test_summary_single_adapter(self):
        rtl = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)
        manager = AdapterManager()
        manager.adapters = [rtl, qca]
        manager._assign_roles()

        text = manager.summary()
        self.assertIn("Dual-adapter", text)
        self.assertNotIn("Tri-adapter", text)

    def test_summary_dual_adapter(self):
        rtl1 = _make_adapter("wlan0", "RTL8812AU", "88XXau")
        qca = _make_adapter("wlan1", "QCA9xxx", "ath10k", monitor=True, injection=True)
        rtl2 = _make_adapter("wlan2", "RTL8812AU", "88XXau")
        manager = AdapterManager()
        manager.adapters = [rtl1, qca, rtl2]
        manager._assign_roles()

        text = manager.summary()
        self.assertIn("Tri-adapter", text)
        self.assertIn("AP: wlan2", text)


if __name__ == "__main__":
    unittest.main()
