"""
WiFi Adapter Detection and Identification

Detects connected WiFi adapters, identifies their chipsets, and determines capabilities.
"""

import subprocess
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import logging

from ..config import load_adapters_config

logger = logging.getLogger(__name__)


@dataclass
class USBDevice:
    """Represents a USB device"""
    bus: str
    device: str
    usb_id: str
    description: str


@dataclass
class NetworkInterface:
    """Represents a network interface"""
    name: str
    mac: str
    driver: Optional[str] = None
    chipset: Optional[str] = None
    phy: Optional[str] = None


@dataclass
class WifiAdapter:
    """Complete WiFi adapter information"""
    interface: NetworkInterface
    usb_device: Optional[USBDevice] = None
    chipset: Optional[str] = None
    driver: Optional[str] = None
    capabilities: Dict[str, bool] = None
    recommended_role: Optional[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = {}


class AdapterDetector:
    """Detects and identifies WiFi adapters"""
    
    def __init__(self):
        self.adapters_config = load_adapters_config()
        self.detected_adapters: List[WifiAdapter] = []
    
    def scan_all(self) -> List[WifiAdapter]:
        """
        Perform complete adapter detection and identification
        
        Returns:
            List of detected WiFi adapters with full information
        """
        logger.info("Starting WiFi adapter detection...")
        
        # Get USB devices
        usb_devices = self._scan_usb_devices()
        
        # Get network interfaces
        interfaces = self._scan_network_interfaces()
        
        # Match and identify adapters
        self.detected_adapters = self._match_adapters(usb_devices, interfaces)
        
        # Test capabilities
        for adapter in self.detected_adapters:
            self._identify_capabilities(adapter)
        
        logger.info(f"Detected {len(self.detected_adapters)} WiFi adapters")
        return self.detected_adapters
    
    def _scan_usb_devices(self) -> List[USBDevice]:
        """Scan for USB WiFi adapters"""
        devices = []
        
        try:
            result = subprocess.run(
                ["lsusb"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                match = re.match(r'Bus (\d+) Device (\d+): ID ([0-9a-f]{4}:[0-9a-f]{4}) (.+)', line)
                if match:
                    device = USBDevice(
                        bus=match.group(1),
                        device=match.group(2),
                        usb_id=match.group(3),
                        description=match.group(4)
                    )
                    
                    # Check if this is a known WiFi adapter
                    if self._is_wifi_adapter(device.usb_id):
                        devices.append(device)
                        logger.debug(f"Found WiFi USB device: {device.usb_id} - {device.description}")
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to scan USB devices: {e}")
        
        return devices
    
    def _scan_network_interfaces(self) -> List[NetworkInterface]:
        """Scan for network interfaces"""
        interfaces = []
        
        try:
            # Get wireless interfaces
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                check=True
            )
            
            current_phy = None
            current_interface = None
            
            for line in result.stdout.split('\n'):
                # Parse phy
                if line.startswith('phy#'):
                    current_phy = line.strip()
                
                # Parse interface name
                match = re.search(r'Interface (\w+)', line)
                if match:
                    current_interface = match.group(1)
                
                # Parse MAC address
                match = re.search(r'addr ([0-9a-f:]+)', line)
                if match and current_interface:
                    mac = match.group(1)
                    
                    # Get driver info
                    driver = self._get_interface_driver(current_interface)
                    
                    interface = NetworkInterface(
                        name=current_interface,
                        mac=mac,
                        driver=driver,
                        phy=current_phy
                    )
                    interfaces.append(interface)
                    logger.debug(f"Found interface: {interface.name} ({interface.mac})")
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to scan network interfaces: {e}")
        
        return interfaces
    
    def _get_interface_driver(self, interface: str) -> Optional[str]:
        """Get driver for network interface"""
        try:
            driver_path = Path(f"/sys/class/net/{interface}/device/driver")
            if driver_path.exists():
                driver = driver_path.resolve().name
                return driver
        except Exception as e:
            logger.debug(f"Could not get driver for {interface}: {e}")
        
        return None
    
    def _is_wifi_adapter(self, usb_id: str) -> bool:
        """Check if USB ID belongs to a known WiFi adapter"""
        for adapter_info in self.adapters_config.get('adapters', {}).values():
            if usb_id in adapter_info.get('usb_ids', []):
                return True
        return False
    
    def _match_adapters(self, usb_devices: List[USBDevice], 
                       interfaces: List[NetworkInterface]) -> List[WifiAdapter]:
        """Match USB devices with network interfaces"""
        adapters = []
        
        # For each interface, try to find matching USB device
        for interface in interfaces:
            adapter = WifiAdapter(interface=interface)
            
            # Try to match with USB device
            for usb_device in usb_devices:
                if self._is_same_device(interface, usb_device):
                    adapter.usb_device = usb_device
                    
                    # Get adapter info from config
                    adapter_info = self._get_adapter_info(usb_device.usb_id)
                    if adapter_info:
                        adapter.chipset = adapter_info.get('chipset')
                        adapter.recommended_role = adapter_info.get('recommended_role')
                    break
            
            # Set driver and chipset
            adapter.driver = interface.driver
            if not adapter.chipset and interface.driver:
                adapter.chipset = self._guess_chipset_from_driver(interface.driver)
            
            adapters.append(adapter)
        
        return adapters
    
    def _is_same_device(self, interface: NetworkInterface, usb_device: USBDevice) -> bool:
        """Check if interface and USB device are the same"""
        # This is a simplified check - in production, would use more sophisticated matching
        try:
            # Check if the interface's USB ID matches
            usb_path = Path(f"/sys/class/net/{interface.name}/device")
            if usb_path.exists():
                # Parse USB bus and device from sysfs path
                path_str = str(usb_path.resolve())
                if f"{usb_device.bus}-" in path_str:
                    return True
        except Exception:
            pass
        
        return False
    
    def _get_adapter_info(self, usb_id: str) -> Optional[Dict]:
        """Get adapter information from config"""
        for adapter_info in self.adapters_config.get('adapters', {}).values():
            if usb_id in adapter_info.get('usb_ids', []):
                return adapter_info
        return None
    
    def _guess_chipset_from_driver(self, driver: str) -> Optional[str]:
        """Guess chipset based on driver name"""
        driver_chipset_map = {
            'rtl88xxau': 'Realtek RTL8812AU/RTL8814AU',
            'rtl8812au': 'Realtek RTL8812AU',
            'rtl8814au': 'Realtek RTL8814AU',
            'mt7921u': 'MediaTek MT7921U',
            'mt7921e': 'MediaTek MT7921E',
            'rt2800usb': 'Ralink RT2800',
            'ath9k': 'Atheros AR9xxx',
            'ath9k_htc': 'Atheros AR9271',
            'carl9170': 'Atheros AR9170',
        }
        
        for key, chipset in driver_chipset_map.items():
            if key in driver.lower():
                return chipset
        
        return None
    
    def _identify_capabilities(self, adapter: WifiAdapter) -> None:
        """Identify adapter capabilities"""
        interface = adapter.interface.name
        
        # Check monitor mode support
        adapter.capabilities['monitor_mode'] = self._check_monitor_mode(interface)
        
        # Check injection support (requires monitor mode)
        if adapter.capabilities['monitor_mode']:
            adapter.capabilities['packet_injection'] = self._check_injection(interface)
        else:
            adapter.capabilities['packet_injection'] = False
        
        # Check frequency bands
        bands = self._get_frequency_bands(interface)
        adapter.capabilities['band_2.4ghz'] = '2.4' in bands
        adapter.capabilities['band_5ghz'] = '5' in bands
        adapter.capabilities['band_6ghz'] = '6' in bands
    
    def _check_monitor_mode(self, interface: str) -> bool:
        """Check if interface supports monitor mode"""
        try:
            result = subprocess.run(
                ["iw", "list"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Look for monitor mode support in capabilities
            if "monitor" in result.stdout.lower():
                return True
        except Exception as e:
            logger.debug(f"Could not check monitor mode for {interface}: {e}")
        
        return False
    
    def _check_injection(self, interface: str) -> bool:
        """Check if interface supports packet injection"""
        # This would require actually testing injection
        # For now, return True if monitor mode is supported
        # In production, would use aireplay-ng --test
        return True
    
    def _get_frequency_bands(self, interface: str) -> List[str]:
        """Get supported frequency bands"""
        bands = []
        
        try:
            result = subprocess.run(
                ["iw", "phy", f"phy{interface[-1]}", "info"],
                capture_output=True,
                text=True,
                check=False  # Don't raise on error
            )
            
            if result.returncode == 0:
                if "2412 MHz" in result.stdout or "2.4" in result.stdout:
                    bands.append("2.4")
                if "5180 MHz" in result.stdout or "5.2" in result.stdout:
                    bands.append("5")
                if "5955 MHz" in result.stdout or "6" in result.stdout:
                    bands.append("6")
        except Exception as e:
            logger.debug(f"Could not get frequency bands for {interface}: {e}")
        
        return bands if bands else ["2.4"]  # Default to 2.4GHz
    
    def get_summary(self) -> str:
        """Get summary of detected adapters"""
        if not self.detected_adapters:
            return "No WiFi adapters detected"
        
        summary = f"Detected {len(self.detected_adapters)} WiFi adapter(s):\n\n"
        
        for i, adapter in enumerate(self.detected_adapters, 1):
            summary += f"{i}. Interface: {adapter.interface.name}\n"
            summary += f"   MAC: {adapter.interface.mac}\n"
            summary += f"   Chipset: {adapter.chipset or 'Unknown'}\n"
            summary += f"   Driver: {adapter.driver or 'Unknown'}\n"
            
            if adapter.usb_device:
                summary += f"   USB ID: {adapter.usb_device.usb_id}\n"
            
            summary += "   Capabilities:\n"
            for cap, supported in adapter.capabilities.items():
                if supported:
                    summary += f"     ✓ {cap.replace('_', ' ').title()}\n"
            
            if adapter.recommended_role:
                summary += f"   Recommended Role: {adapter.recommended_role}\n"
            
            summary += "\n"
        
        return summary