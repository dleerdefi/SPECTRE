#!/bin/bash

# WiFi Launchpad - One-Click Installer
# Zero friction installation for Kali Linux users

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ASCII Art Banner
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     WiFi Launchpad - First Success Engine               ║
║     Your first handshake in 10 minutes, guaranteed!     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}[*] Starting WiFi Launchpad Installation...${NC}"
echo -e "${YELLOW}[!] This installer will:${NC}"
echo "    ✓ Check your system compatibility"
echo "    ✓ Install required dependencies"
echo "    ✓ Detect your WiFi adapters"
echo "    ✓ Install missing drivers automatically"
echo "    ✓ Set up the environment"
echo ""

# Check if running on Kali
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}[!] Warning: This doesn't appear to be Kali Linux${NC}"
    echo "    WiFi Launchpad is designed for Kali Linux"
    read -p "    Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[!] This script should not be run as root${NC}"
   echo "    It will request sudo when needed"
   exit 1
fi

echo -e "${GREEN}[1/6] Updating package lists...${NC}"
sudo apt update

echo -e "${GREEN}[2/6] Installing core dependencies...${NC}"
# Core system tools
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    build-essential \
    dkms

# WiFi tools
sudo apt install -y \
    aircrack-ng \
    hashcat \
    john \
    reaver \
    bully \
    macchanger \
    wireless-tools \
    net-tools \
    tshark \
    hcxtools \
    hcxdumptool

# Additional utilities
sudo apt install -y \
    pciutils \
    usbutils \
    rfkill \
    iw

echo -e "${GREEN}[3/6] Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}[4/6] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}[5/6] Detecting WiFi adapters...${NC}"
echo -e "${YELLOW}[*] Found the following USB WiFi adapters:${NC}"
lsusb | grep -E "Realtek|MediaTek|Ralink|Atheros|ALFA" || echo "No known adapters detected via USB"

echo ""
echo -e "${YELLOW}[*] Network interfaces:${NC}"
ip link show | grep -E "wlan|wlp" || echo "No wireless interfaces found"

echo ""
echo -e "${GREEN}[6/6] Running pre-flight checks...${NC}"

# Check for specific adapters and install drivers if needed
if lsusb | grep -q "0bda:8812"; then
    echo -e "${GREEN}[✓] ALFA AWUS036ACH detected (RTL8812AU)${NC}"
    if ! lsmod | grep -q "88XXau"; then
        echo -e "${YELLOW}[!] Driver not loaded. Installing...${NC}"
        sudo apt install -y realtek-rtl88xxau-dkms || {
            echo -e "${YELLOW}[!] Package not found. Building from source...${NC}"
            git clone https://github.com/aircrack-ng/rtl8812au.git /tmp/rtl8812au
            cd /tmp/rtl8812au
            sudo make dkms_install
            cd -
        }
    fi
fi

if lsusb | grep -q "0e8d:7961"; then
    echo -e "${GREEN}[✓] ALFA AWUS036AXML detected (MT7921U)${NC}"
    if ! lsmod | grep -q "mt7921u"; then
        echo -e "${YELLOW}[!] Installing MediaTek firmware...${NC}"
        sudo apt install -y firmware-misc-nonfree
    fi
fi

# Create necessary directories
echo -e "${GREEN}[*] Creating directory structure...${NC}"
mkdir -p captures wordlists logs

# Download basic wordlist if not present
if [ ! -f "wordlists/rockyou.txt" ]; then
    echo -e "${GREEN}[*] Downloading rockyou wordlist...${NC}"
    if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
        ln -s /usr/share/wordlists/rockyou.txt wordlists/rockyou.txt
    elif [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
        gunzip -c /usr/share/wordlists/rockyou.txt.gz > wordlists/rockyou.txt
    fi
fi

# Make launch.sh executable if it exists
if [ -f "launch.sh" ]; then
    chmod +x launch.sh
    echo -e "${GREEN}[✓] launch.sh is ready${NC}"
else
    echo -e "${YELLOW}[!] launch.sh not found - creating basic launcher${NC}"
    cat > launch.sh << 'LAUNCHER'
#!/bin/bash
source venv/bin/activate
python3 -m quickstart.wizard
LAUNCHER
    chmod +x launch.sh
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Installation Complete! 🎉                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}To start WiFi Launchpad, run:${NC}"
echo -e "${YELLOW}    ./launch.sh${NC}"
echo ""
echo -e "${BLUE}Or for advanced mode:${NC}"
echo -e "${YELLOW}    source venv/bin/activate${NC}"
echo -e "${YELLOW}    python cli.py --advanced${NC}"
echo ""
echo -e "${GREEN}Ready to capture your first handshake? Let's go! 🚀${NC}"