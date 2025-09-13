#!/usr/bin/env python3
"""
WiFi Adapter Management

Handles adapter detection, configuration, mode switching, and role assignment.
Optimized for dual-adapter setups with automatic role allocation.
"""

import subprocess
import re
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class WifiAdapter:
    """Represents a WiFi adapter with all its properties"""
    interface: str
    mac_address: str
    phy: str
    driver: Optional[str] = None
    chipset: Optional[str] = None
    usb_id: Optional[str] = None
    
    # Capabilities
    monitor_mode: bool = False
    packet_injection: bool = False
    frequency_bands: List[str] = field(default_factory=list)
    supported_modes: List[str] = field(default_factory=list)
    
    # Current state
    current_mode: str = "managed"
    current_channel: Optional[int] = None
    tx_power: Optional[int] = None
    
    # Role assignment
    assigned_role: Optional[str] = None  # 'monitor', 'injection', 'management'
    
    def __str__(self):
        return f"{self.interface} ({self.chipset or 'Unknown'}) - {self.assigned_role or 'No role'}"


class AdapterManager:
    """Manages WiFi adapters for optimal dual-adapter operation"""
    
    # Known optimal configurations
    OPTIMAL_CONFIGS = {
        "RTL8812AU": {
            "role": "monitor",
            "tx_power": 30,
            "preferred_channels": [1, 6, 11, 36, 40, 44, 48]
        },
        "MT7921U": {
            "role": "injection",
            "tx_power": 30,
            "injection_rate": 0.93
        },
        "RT3070": {
            "role": "legacy",
            "tx_power": 30,
            "bands": ["2.4GHz"]
        }
    }
    
    def __init__(self):
        self.adapters: List[WifiAdapter] = []
        self.monitor_adapter: Optional[WifiAdapter] = None
        self.injection_adapter: Optional[WifiAdapter] = None
        self.management_adapter: Optional[WifiAdapter] = None
        
    def discover_adapters(self) -> List[WifiAdapter]:
        """Discover all WiFi adapters on the system"""
        self.adapters = []
        
        # Get all wireless interfaces
        interfaces = self._get_wireless_interfaces()
        
        for iface in interfaces:
            adapter = self._get_adapter_info(iface)
            if adapter:
                self._detect_capabilities(adapter)
                self.adapters.append(adapter)
        
        # Auto-assign roles for optimal configuration
        self._assign_roles()
        
        logger.info(f"Discovered {len(self.adapters)} WiFi adapters")
        return self.adapters
    
    def _get_wireless_interfaces(self) -> List[str]:
        """Get list of wireless interfaces"""
        interfaces = []
        
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split('Interface')[1].strip()
                    interfaces.append(iface)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get interfaces: {e}")
        
        return interfaces
    
    def _get_adapter_info(self, interface: str) -> Optional[WifiAdapter]:
        """Get detailed information about an adapter"""
        try:
            # Get basic info
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                check=True
            )
            
            adapter = WifiAdapter(interface=interface, mac_address="", phy="")
            
            for line in result.stdout.split('\n'):
                if 'addr' in line:
                    adapter.mac_address = line.split('addr')[1].strip()
                elif 'wiphy' in line:
                    adapter.phy = f"phy{line.split('wiphy')[1].strip()}"
                elif 'type' in line:
                    adapter.current_mode = line.split('type')[1].strip()
                elif 'channel' in line:
                    match = re.search(r'channel (\d+)', line)
                    if match:
                        adapter.current_channel = int(match.group(1))
                elif 'txpower' in line:
                    match = re.search(r'(\d+\.\d+) dBm', line)
                    if match:
                        adapter.tx_power = float(match.group(1))
            
            # Get driver info
            driver_path = Path(f"/sys/class/net/{interface}/device/driver")
            if driver_path.exists():
                adapter.driver = driver_path.resolve().name
            
            # Detect chipset
            adapter.chipset = self._detect_chipset(interface, adapter.driver)
            
            # Get USB ID if USB device
            adapter.usb_id = self._get_usb_id(interface)
            
            return adapter
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get info for {interface}: {e}")
            return None
    
    def _detect_chipset(self, interface: str, driver: Optional[str]) -> Optional[str]:
        """Detect adapter chipset"""
        # Check USB devices
        try:
            result = subprocess.run(["lsusb"], capture_output=True, text=True)
            
            # Known USB ID to chipset mappings
            usb_chipset_map = {
                "0bda:8812": "RTL8812AU",
                "0bda:8813": "RTL8814AU",
                "0e8d:7961": "MT7921U",
                "148f:3070": "RT3070",
                "148f:3072": "RT3072",
                "0cf3:9271": "AR9271"
            }
            
            for usb_id, chipset in usb_chipset_map.items():
                if usb_id in result.stdout:
                    return chipset
        except:
            pass
        
        # Guess from driver name
        if driver:
            driver_chipset_map = {
                "88XXau": "RTL8812AU/8814AU",
                "8812au": "RTL8812AU",
                "8814au": "RTL8814AU",
                "mt7921u": "MT7921U",
                "rt2800usb": "RT2800",
                "ath9k_htc": "AR9271",
                "ath9k": "AR9xxx"
            }
            
            for key, chipset in driver_chipset_map.items():
                if key in driver.lower():
                    return chipset
        
        return None
    
    def _get_usb_id(self, interface: str) -> Optional[str]:
        """Get USB ID for interface if it's a USB device"""
        try:
            # Check if it's a USB device
            device_path = Path(f"/sys/class/net/{interface}/device")
            if device_path.exists():
                # Try to find idVendor and idProduct
                vendor_path = device_path / "idVendor"
                product_path = device_path / "idProduct"
                
                if vendor_path.exists() and product_path.exists():
                    vendor = vendor_path.read_text().strip()
                    product = product_path.read_text().strip()
                    return f"{vendor}:{product}"
        except:
            pass
        
        return None
    
    def _detect_capabilities(self, adapter: WifiAdapter):
        """Detect adapter capabilities"""
        # Check supported modes
        try:
            result = subprocess.run(
                ["iw", "phy", adapter.phy, "info"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Check for monitor mode support
            if "monitor" in result.stdout.lower():
                adapter.monitor_mode = True
                adapter.supported_modes.append("monitor")
            
            # Check frequency bands
            if "2412 MHz" in result.stdout or "2.4" in result.stdout:
                adapter.frequency_bands.append("2.4GHz")
            if "5180 MHz" in result.stdout or "5" in result.stdout:
                adapter.frequency_bands.append("5GHz")
            if "5955 MHz" in result.stdout or "6" in result.stdout:
                adapter.frequency_bands.append("6GHz")
            
            # Assume injection works if monitor mode is supported
            adapter.packet_injection = adapter.monitor_mode
            
        except:
            pass
    
    def _assign_roles(self):
        """Automatically assign roles based on adapter capabilities"""
        # Clear existing roles
        self.monitor_adapter = None
        self.injection_adapter = None
        self.management_adapter = None
        
        # Sort adapters by capability score
        def score_adapter(adapter: WifiAdapter) -> int:
            score = 0
            if adapter.monitor_mode:
                score += 10
            if adapter.packet_injection:
                score += 10
            if "5GHz" in adapter.frequency_bands:
                score += 5
            if adapter.chipset in self.OPTIMAL_CONFIGS:
                score += 20
            return score
        
        sorted_adapters = sorted(self.adapters, key=score_adapter, reverse=True)
        
        # Assign roles based on known optimal configurations
        for adapter in sorted_adapters:
            if adapter.chipset in self.OPTIMAL_CONFIGS:
                config = self.OPTIMAL_CONFIGS[adapter.chipset]
                role = config["role"]
                
                if role == "monitor" and not self.monitor_adapter:
                    adapter.assigned_role = "monitor"
                    self.monitor_adapter = adapter
                elif role == "injection" and not self.injection_adapter:
                    adapter.assigned_role = "injection"
                    self.injection_adapter = adapter
        
        # Assign remaining adapters
        for adapter in sorted_adapters:
            if adapter.assigned_role:
                continue
                
            if not self.monitor_adapter and adapter.monitor_mode:
                adapter.assigned_role = "monitor"
                self.monitor_adapter = adapter
            elif not self.injection_adapter and adapter.packet_injection:
                adapter.assigned_role = "injection"
                self.injection_adapter = adapter
            elif not self.management_adapter:
                adapter.assigned_role = "management"
                self.management_adapter = adapter
    
    def enable_monitor_mode(self, adapter: WifiAdapter) -> bool:
        """Enable monitor mode on an adapter"""
        if adapter.current_mode == "monitor":
            logger.info(f"{adapter.interface} already in monitor mode")
            return True
        
        try:
            # Bring interface down
            subprocess.run(
                ["sudo", "ip", "link", "set", adapter.interface, "down"],
                check=True
            )
            
            # Set monitor mode
            subprocess.run(
                ["sudo", "iw", "dev", adapter.interface, "set", "type", "monitor"],
                check=True
            )
            
            # Bring interface up
            subprocess.run(
                ["sudo", "ip", "link", "set", adapter.interface, "up"],
                check=True
            )
            
            adapter.current_mode = "monitor"
            logger.info(f"Enabled monitor mode on {adapter.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable monitor mode on {adapter.interface}: {e}")
            return False
    
    def disable_monitor_mode(self, adapter: WifiAdapter) -> bool:
        """Disable monitor mode and return to managed mode"""
        if adapter.current_mode == "managed":
            return True
        
        try:
            subprocess.run(
                ["sudo", "ip", "link", "set", adapter.interface, "down"],
                check=True
            )
            
            subprocess.run(
                ["sudo", "iw", "dev", adapter.interface, "set", "type", "managed"],
                check=True
            )
            
            subprocess.run(
                ["sudo", "ip", "link", "set", adapter.interface, "up"],
                check=True
            )
            
            adapter.current_mode = "managed"
            logger.info(f"Disabled monitor mode on {adapter.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable monitor mode on {adapter.interface}: {e}")
            return False
    
    def set_channel(self, adapter: WifiAdapter, channel: int) -> bool:
        """Set adapter to specific channel"""
        try:
            subprocess.run(
                ["sudo", "iw", "dev", adapter.interface, "set", "channel", str(channel)],
                check=True
            )
            
            adapter.current_channel = channel
            logger.info(f"Set {adapter.interface} to channel {channel}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set channel on {adapter.interface}: {e}")
            return False
    
    def test_injection(self, adapter: WifiAdapter) -> bool:
        """Test packet injection capability"""
        if adapter.current_mode != "monitor":
            self.enable_monitor_mode(adapter)
        
        try:
            # Run injection test
            result = subprocess.run(
                ["sudo", "aireplay-ng", "--test", adapter.interface],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check for success indicators
            if "Injection is working!" in result.stdout:
                logger.info(f"Injection test passed on {adapter.interface}")
                return True
            else:
                logger.warning(f"Injection test failed on {adapter.interface}")
                return False
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error(f"Injection test error on {adapter.interface}: {e}")
            return False
    
    def get_optimal_setup(self) -> Dict[str, Optional[WifiAdapter]]:
        """Get the optimal adapter configuration"""
        return {
            "monitor": self.monitor_adapter,
            "injection": self.injection_adapter,
            "management": self.management_adapter
        }
    
    def summary(self) -> str:
        """Get summary of adapter configuration"""
        lines = [f"Found {len(self.adapters)} WiFi adapter(s):"]
        
        for adapter in self.adapters:
            lines.append(f"  • {adapter.interface}: {adapter.chipset or 'Unknown'} ({adapter.assigned_role or 'No role'})")
            lines.append(f"    - Mode: {adapter.current_mode}")
            lines.append(f"    - Bands: {', '.join(adapter.frequency_bands)}")
            if adapter.current_channel:
                lines.append(f"    - Channel: {adapter.current_channel}")
        
        if self.monitor_adapter and self.injection_adapter:
            lines.append("\n✅ Dual-adapter configuration ready!")
            lines.append(f"  Monitor: {self.monitor_adapter.interface}")
            lines.append(f"  Injection: {self.injection_adapter.interface}")
        
        return '\n'.join(lines)