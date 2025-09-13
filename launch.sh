#!/bin/bash

#############################################
# WiFi Launchpad - Launch Script
# Your first handshake in 10 minutes!
#############################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ASCII Art Banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
 __      ___  __ _   _                           _                     _
 \ \    / (_)/ _(_) | |   __ _ _   _ _ __   ___| |__  _ __   __ _  __| |
  \ \/\/ /| | |_| | | |  / _` | | | | '_ \ / __| '_ \| '_ \ / _` |/ _` |
   \    / | |  _| | | |_| (_| | |_| | | | | (__| | | | |_) | (_| | (_| |
    \/\/  |_|_| |_| |_____\__,_|\__,_|_| |_|\___|_| |_| .__/ \__,_|\__,_|
                                                       |_|
EOF
    echo -e "${NC}"
    echo -e "${BOLD}Your first WiFi handshake in 10 minutes, guaranteed!${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}⚠️  This tool requires root privileges${NC}"
        echo -e "${CYAN}Please run with sudo: ${BOLD}sudo ./launch.sh${NC}"
        exit 1
    fi
}

# Check Python installation
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is not installed${NC}"
        echo -e "${CYAN}Please run ./install.sh first${NC}"
        exit 1
    fi

    # Check Python version
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    required_version="3.8"

    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        echo -e "${RED}❌ Python $python_version detected, but $required_version+ required${NC}"
        exit 1
    fi
}

# Check if dependencies are installed
check_dependencies() {
    echo -e "${CYAN}🔍 Checking dependencies...${NC}"

    missing_deps=()

    # Check critical tools
    for tool in aircrack-ng airodump-ng aireplay-ng iw; do
        if ! command -v $tool &> /dev/null; then
            missing_deps+=($tool)
        fi
    done

    # Check Python packages in venv
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
        if ! python3 -c "import rich" &> /dev/null 2>&1; then
            missing_deps+=("python3-rich (in venv)")
        fi
    else
        missing_deps+=("venv not created")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${YELLOW}⚠️  Missing dependencies: ${missing_deps[*]}${NC}"
        echo -e "${CYAN}Run ./install.sh to install all dependencies${NC}"
        read -p "Would you like to run install.sh now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ./install.sh
        else
            exit 1
        fi
    fi
}

# Quick adapter check
check_adapters() {
    echo -e "${CYAN}🔍 Detecting WiFi adapters...${NC}"

    # Check for wireless interfaces
    if ! ls /sys/class/net/ | grep -q "wlan"; then
        echo -e "${YELLOW}⚠️  No WiFi adapters detected${NC}"
        echo -e "Please connect a WiFi adapter and try again"
        echo -e "Recommended: ALFA AWUS036ACH or AWUS036AXML"
        exit 1
    fi

    echo -e "${GREEN}✅ WiFi adapter(s) detected${NC}"
}

# Main menu
show_menu() {
    echo ""
    echo -e "${BOLD}${CYAN}Choose your path:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} 🚀 ${BOLD}First Success Wizard${NC} (Recommended for beginners)"
    echo -e "     ${BLUE}Interactive tutorial using your mobile hotspot${NC}"
    echo ""
    echo -e "  ${GREEN}2)${NC} 🔍 ${BOLD}Scan Networks${NC}"
    echo -e "     ${BLUE}Discover WiFi networks around you${NC}"
    echo ""
    echo -e "  ${GREEN}3)${NC} 🎯 ${BOLD}Capture Handshake${NC}"
    echo -e "     ${BLUE}Target specific network for handshake capture${NC}"
    echo ""
    echo -e "  ${GREEN}4)${NC} ⚙️  ${BOLD}Advanced Mode${NC}"
    echo -e "     ${BLUE}Full CLI with all features${NC}"
    echo ""
    echo -e "  ${GREEN}5)${NC} 📚 ${BOLD}Help & Documentation${NC}"
    echo ""
    echo -e "  ${GREEN}0)${NC} Exit"
    echo ""
}

# Activate venv if it exists
activate_venv() {
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi
}

# Launch wizard
launch_wizard() {
    echo -e "${CYAN}🚀 Launching First Success Wizard...${NC}"
    echo ""
    activate_venv
    python3 -m quickstart.wizard
}

# Launch scanner
launch_scanner() {
    echo -e "${CYAN}🔍 Starting network scanner...${NC}"
    echo ""
    activate_venv
    python3 cli.py scan
}

# Launch capture
launch_capture() {
    echo -e "${CYAN}🎯 Starting handshake capture...${NC}"
    echo ""

    # Get target info
    read -p "Enter target BSSID (MAC address): " bssid
    read -p "Enter channel number: " channel

    activate_venv
    python3 cli.py capture --bssid "$bssid" --channel "$channel"
}

# Launch advanced CLI
launch_advanced() {
    echo -e "${CYAN}⚙️  Launching advanced mode...${NC}"
    echo ""
    activate_venv
    python3 cli.py --advanced
}

# Show help
show_help() {
    echo -e "${CYAN}📚 WiFi Launchpad Help${NC}"
    echo ""
    echo -e "${BOLD}Quick Start:${NC}"
    echo "  1. Choose option 1 (First Success Wizard)"
    echo "  2. Set up your phone's hotspot"
    echo "  3. Follow the interactive tutorial"
    echo "  4. Capture your first handshake!"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo "  ./launch.sh          - Start interactive menu"
    echo "  ./install.sh         - Install dependencies"
    echo "  python3 cli.py       - Direct CLI access"
    echo ""
    echo -e "${BOLD}Documentation:${NC}"
    echo "  README.md           - Project overview"
    echo "  docs/tutorial.md    - Detailed tutorial"
    echo "  docs/hardware.md    - Hardware guide"
    echo ""
    echo -e "${BOLD}Support:${NC}"
    echo "  GitHub: https://github.com/dleerdefi/wifi-launchpad"
    echo ""
    read -p "Press Enter to continue..."
}

# Main execution
main() {
    clear
    show_banner

    # Checks
    check_root
    check_python
    check_dependencies
    check_adapters

    # Main loop
    while true; do
        show_menu
        read -p "Enter your choice [0-5]: " choice

        case $choice in
            1)
                launch_wizard
                break
                ;;
            2)
                launch_scanner
                break
                ;;
            3)
                launch_capture
                break
                ;;
            4)
                launch_advanced
                break
                ;;
            5)
                show_help
                ;;
            0)
                echo -e "${GREEN}Thanks for using WiFi Launchpad! 👋${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
    done
}

# Run main function
main "$@"