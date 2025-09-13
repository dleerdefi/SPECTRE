# WiFi Launchpad - Development Specification

## Project Overview
**WiFi Launchpad** is a production-grade WiFi reconnaissance and penetration testing framework designed to be the most user-friendly yet powerful WiFi security testing platform for Kali Linux users.

## Mission Statement
Eliminate the barriers that cause 90% of new Kali users to quit: driver issues, command-line complexity, and lack of foundational knowledge. Guide users from zero to their first successful WPA2 handshake capture in under 10 minutes.

## Core Architecture

### System Requirements
- **OS**: Kali Linux 2024.x or newer
- **Python**: 3.11+
- **Database**: PostgreSQL 16 with TimescaleDB
- **Cache**: Redis 7+
- **Hardware**: Dual WiFi adapters with monitor mode support

### Technology Stack
- **Backend**: Python with FastAPI
- **CLI**: Click framework
- **Database ORM**: SQLAlchemy 2.0
- **Job Queue**: Celery with Redis
- **Monitoring**: Prometheus + Grafana
- **Dashboard**: Streamlit or React
- **Testing**: pytest with coverage

## Hardware Configuration

### Dual-Adapter Strategy
```yaml
Primary Adapter (Monitoring):
  Model: ALFA AWUS036ACH
  Chipset: Realtek RTL8812AU
  Interface: wlan0
  Role: Continuous passive monitoring
  Capabilities:
    - Dual-band (2.4/5 GHz)
    - High-gain antenna
    - Extended range monitoring

Secondary Adapter (Injection):
  Model: ALFA AWUS036AXML
  Chipset: MediaTek MT7921U
  Interface: wlan2/wlan2mon
  Role: Active attacks and injection
  Capabilities:
    - WiFi 6 support
    - Superior injection rates
    - Low latency deauth
```

## Module Specifications

### 1. Pre-Flight Check System (`src/preflight/`)

#### Purpose
Proactively identify and resolve system issues before the user encounters failures.

#### Components

**system_check.py**
```python
class SystemChecker:
    """Validates Kali Linux environment and dependencies"""
    
    def check_os(self) -> CheckResult
    def check_tools(self) -> List[ToolStatus]
    def check_permissions(self) -> PermissionStatus
    def auto_fix_issues(self) -> List[FixResult]
```

**adapter_detect.py**
```python
class AdapterDetector:
    """Identifies WiFi adapters and their capabilities"""
    
    def scan_usb_devices(self) -> List[USBDevice]
    def identify_chipset(self, device: USBDevice) -> ChipsetInfo
    def test_capabilities(self, interface: str) -> AdapterCapabilities
    def recommend_role(self, adapters: List[Adapter]) -> RoleAssignment
```

**driver_manager.py**
```python
class DriverManager:
    """Automated driver installation and management"""
    
    DRIVER_MAP = {
        "0bda:8812": "realtek-rtl88xxau-dkms",  # RTL8812AU
        "0e8d:7961": "mt7921u",                 # MT7921U
        "148f:3070": "firmware-ralink",         # RT3070
    }
    
    def detect_missing_drivers(self) -> List[MissingDriver]
    def install_driver(self, chipset: str) -> InstallResult
    def compile_from_source(self, repo_url: str) -> CompileResult
```

### 2. Reconnaissance Engine (`src/recon/`)

#### Purpose
Continuous, intelligent network discovery with real-time database updates.

#### Components

**scanner.py**
```python
class NetworkScanner:
    """Airodump-ng wrapper with intelligent channel hopping"""
    
    def start_scan(self, interface: str, channels: List[int] = None)
    def parse_output(self, csv_file: str) -> List[Network]
    def intelligent_hop(self) -> ChannelStrategy
    def focus_on_target(self, bssid: str)
```

**db_ingestion.py**
```python
class DataIngestion:
    """Real-time database updates with deduplication"""
    
    def __init__(self, db_url: str, batch_size: int = 100)
    def ingest_networks(self, networks: List[Network])
    def update_signal_strength(self, bssid: str, rssi: int)
    def detect_new_clients(self, clients: List[Client])
```

**target_filter.py**
```python
class TargetFilter:
    """Include/exclude logic with regex support"""
    
    def load_filters(self, config_file: str)
    def is_target(self, network: Network) -> bool
    def prioritize_targets(self, networks: List[Network]) -> List[Network]
```

### 3. Attack Orchestration (`src/attacks/`)

#### Purpose
Automated, intelligent attack workflows with success validation.

#### Attack Modules

**handshake/capture.py**
```python
class HandshakeCapture:
    """Automated WPA/WPA2 handshake capture"""
    
    def capture_handshake(self, target: Network) -> Handshake
    def validate_handshake(self, pcap_file: str) -> bool
    def optimize_deauth_strategy(self, clients: List[Client]) -> DeauthPlan
```

**wps/scanner.py**
```python
class WPSScanner:
    """WPS vulnerability detection and exploitation"""
    
    def scan_wps_networks(self) -> List[WPSNetwork]
    def check_wps_lock(self, bssid: str) -> bool
    def attempt_pixie_dust(self, target: WPSNetwork) -> WPSResult
```

**evil_twin/ap_creator.py**
```python
class EvilTwinAP:
    """Rogue access point with captive portal"""
    
    def create_ap(self, target: Network, interface: str)
    def setup_captive_portal(self, template: str = "default")
    def harvest_credentials(self) -> List[Credential]
```

### 4. Distributed Cracking System (`src/cracking/`)

#### Purpose
Leverage local CPU and remote GPU resources for password cracking.

#### Components

**queue_manager.py**
```python
class CrackingQueue:
    """Redis-based job queue with priority management"""
    
    def add_job(self, handshake: Handshake, priority: int = 5)
    def get_next_job(self) -> CrackJob
    def update_progress(self, job_id: str, progress: float)
```

**remote_crack.py**
```python
class RemoteGPUCracker:
    """SSH-based GPU cracking on remote server"""
    
    def connect_to_gpu_server(self, host: str, key_path: str)
    def transfer_handshake(self, pcap_file: str)
    def start_hashcat(self, hash_file: str, wordlist: str) -> JobID
    def monitor_progress(self, job_id: JobID) -> Progress
```

**wordlist_manager.py**
```python
class WordlistManager:
    """Intelligent wordlist selection and optimization"""
    
    WORDLIST_SOURCES = {
        "rockyou": "/usr/share/wordlists/rockyou.txt",
        "seclists": "https://github.com/danielmiessler/SecLists",
        "custom": "/opt/wordlists/custom/"
    }
    
    def download_wordlist(self, source: str)
    def generate_targeted_wordlist(self, ssid: str) -> str
    def apply_rules(self, wordlist: str, rules: List[str]) -> str
```

### 5. Control Interface (`src/api/` & `src/cli/`)

#### API Endpoints
```python
# FastAPI routes
POST   /api/scan/start          # Start reconnaissance
GET    /api/scan/status         # Get scan status
POST   /api/attack/handshake    # Capture handshake
POST   /api/attack/wps          # Start WPS attack
GET    /api/crack/status/{id}   # Check crack status
WS     /api/ws/updates          # Real-time updates
```

#### CLI Commands
```bash
# Click CLI interface
wifi-launchpad preflight        # Run pre-flight checks
wifi-launchpad scan start       # Start scanning
wifi-launchpad attack handshake --target BSSID
wifi-launchpad crack start --handshake FILE
wifi-launchpad sandbox          # Launch "My First Pentest"
```

### 6. "My First Pentest" Sandbox (`src/sandbox/`)

#### Purpose
Guided tutorial ensuring every user achieves their first successful capture.

#### Workflow
```python
class FirstPentestWizard:
    """Step-by-step guided experience"""
    
    STEPS = [
        "detect_adapters",      # Find and validate adapters
        "setup_hotspot",        # Guide mobile hotspot creation
        "explain_monitor_mode", # Educational content
        "capture_handshake",    # Automated capture
        "crack_password",       # Demonstrate cracking
        "celebrate_success"     # Positive reinforcement
    ]
    
    def run_wizard(self) -> WizardResult
```

## Database Schema

### Core Tables
```sql
-- Networks table (extends existing)
ALTER TABLE networks ADD COLUMN IF NOT EXISTS
    vendor VARCHAR(100),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    total_packets BIGINT,
    wps_enabled BOOLEAN,
    wps_locked BOOLEAN,
    target_priority INTEGER DEFAULT 5;

-- Handshakes table (extends existing)
ALTER TABLE handshakes ADD COLUMN IF NOT EXISTS
    quality_score FLOAT,
    capture_method VARCHAR(50),
    deauth_count INTEGER,
    time_to_capture INTERVAL;

-- Attack sessions
CREATE TABLE IF NOT EXISTS attack_sessions (
    id SERIAL PRIMARY KEY,
    session_id UUID DEFAULT gen_random_uuid(),
    started_at TIMESTAMP DEFAULT NOW(),
    ended_at TIMESTAMP,
    attack_type VARCHAR(50),
    target_bssid MACADDR,
    success BOOLEAN,
    notes TEXT
);

-- Adapter profiles
CREATE TABLE IF NOT EXISTS adapter_profiles (
    id SERIAL PRIMARY KEY,
    interface VARCHAR(20) UNIQUE,
    usb_id VARCHAR(9),
    chipset VARCHAR(50),
    driver VARCHAR(100),
    monitor_capable BOOLEAN,
    injection_capable BOOLEAN,
    injection_rate FLOAT,
    last_calibrated TIMESTAMP
);
```

## Configuration Files

### config/.env
```env
# Application
APP_NAME=WiFi-Launchpad
APP_VERSION=1.0.0
LOG_LEVEL=INFO

# Database
DB_HOST=<your-server-ip>
DB_PORT=5432
DB_NAME=wifi_db
DB_USER=<your-db-user>
DB_PASSWORD=<your-db-password>
DB_POOL_SIZE=20

# Redis
REDIS_HOST=<your-server-ip>
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Adapters
MONITOR_INTERFACE=wlan0
INJECTION_INTERFACE=wlan2mon
MANAGEMENT_INTERFACE=wlan1

# GPU Server
GPU_SERVER_ENABLED=true
GPU_SERVER_HOST=
GPU_SERVER_USER=
GPU_SERVER_KEY_PATH=

# Paths
WORDLIST_DIR=/opt/wordlists
CAPTURE_DIR=/opt/captures
LOG_DIR=/var/log/wifi-launchpad
```

### config/adapters.yaml
```yaml
adapters:
  rtl8812au:
    name: "ALFA AWUS036ACH"
    usb_ids: ["0bda:8812", "0bda:8811"]
    driver: "realtek-rtl88xxau-dkms"
    driver_source: "https://github.com/aircrack-ng/rtl8812au"
    capabilities:
      monitor: true
      injection: true
      bands: ["2.4GHz", "5GHz"]
      max_power: 30
    recommended_role: "monitoring"
    
  mt7921u:
    name: "ALFA AWUS036AXML"
    usb_ids: ["0e8d:7961"]
    driver: "mt7921u"
    driver_source: "kernel"
    capabilities:
      monitor: true
      injection: true
      bands: ["2.4GHz", "5GHz", "6GHz"]
      wifi_standard: "WiFi 6"
      max_power: 30
    recommended_role: "injection"
```

### config/targets.yaml
```yaml
# Target configuration
targets:
  include:
    # SSIDs to specifically target
    ssids:
      - "TestNetwork"
      - pattern: "^Corp-.*"  # Regex pattern
    
    # BSSIDs to target
    bssids:
      - "AA:BB:CC:DD:EE:FF"
    
    # Encryption types to target
    encryption:
      - "WPA2"
      - "WPS"
  
  exclude:
    # Never attack these networks
    ssids:
      - "FBI Surveillance Van"
      - "Police"
      - pattern: ".*Hospital.*"
    
    # Protected BSSIDs
    bssids:
      - "11:22:33:44:55:66"
    
    # Skip these encryption types
    encryption:
      - "WPA3"
      - "Enterprise"

  priority:
    # Higher priority targets (1-10)
    high:
      - ssid: "TargetNetwork"
        priority: 10
    
    medium:
      - encryption: "WPS"
        priority: 7
```

## Testing Strategy

### Unit Tests
```python
# tests/test_preflight.py
def test_adapter_detection()
def test_driver_mapping()
def test_monitor_mode_enable()

# tests/test_recon.py
def test_airodump_parsing()
def test_network_classification()
def test_database_ingestion()

# tests/test_attacks.py
def test_handshake_validation()
def test_deauth_injection()
def test_wps_detection()
```

### Integration Tests
```python
# tests/integration/test_workflow.py
def test_full_handshake_capture_workflow()
def test_database_persistence()
def test_api_endpoints()
```

## Deployment

### Docker Compose
```yaml
version: '3.8'

services:
  wifi-launchpad:
    build: .
    network_mode: host
    privileged: true
    volumes:
      - /sys/bus/usb:/sys/bus/usb
      - ./captures:/opt/captures
      - ./wordlists:/opt/wordlists
    environment:
      - DB_HOST=${DB_HOST}
      - REDIS_HOST=${REDIS_HOST}
    devices:
      - /dev/bus/usb:/dev/bus/usb
```

### SystemD Service
```ini
[Unit]
Description=WiFi Launchpad Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wifi-launchpad
ExecStart=/usr/bin/python3 -m src.main
Restart=always

[Install]
WantedBy=multi-user.target
```

## Success Metrics

### Performance KPIs
- Adapter detection accuracy: 100%
- Driver installation success: >95%
- Time to first handshake: <10 minutes
- Handshake capture rate: >90%
- False positive rate: <5%

### User Experience KPIs
- Setup completion rate: >80%
- First success rate: >85%
- User retention: >70%
- Support tickets: <10%

## Security Considerations

### Ethical Usage
- Legal disclaimer on startup
- Confirmation for each attack
- Logging of all activities
- Rate limiting on attacks

### Data Protection
- Encrypted storage of captured handshakes
- Secure credential storage
- API authentication required
- Audit logging enabled

## Maintenance Plan

### Regular Updates
- Weekly wordlist updates
- Monthly driver updates
- Quarterly feature releases
- Security patches as needed

### Monitoring
- Prometheus metrics export
- Grafana dashboards
- Error tracking with Sentry
- Usage analytics

## Documentation

### User Documentation
- Quick Start Guide
- Video Tutorials
- FAQ Section
- Troubleshooting Guide

### Developer Documentation
- API Reference
- Architecture Overview
- Contributing Guidelines
- Plugin Development

## Conclusion

WiFi Launchpad represents a paradigm shift in WiFi penetration testing tools - combining enterprise-grade architecture with unprecedented user-friendliness. By focusing on the "first success" experience while maintaining professional capabilities, this framework will become the standard tool for both beginners and experts in the WiFi security testing community.

---

*Version: 1.0.0*  
*Last Updated: 2024*  
*Author: WiFi Launchpad Team*