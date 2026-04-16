#!/bin/bash

set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
    echo "Run this installer as your normal user. It will request sudo when needed."
    exit 1
fi

echo "Installing SPECTRE dependencies..."
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    git \
    iw \
    aircrack-ng \
    hcxtools \
    hcxdumptool \
    hashcat \
    tshark \
    wireless-tools

echo "Creating virtual environment..."
python3 -m venv venv
. venv/bin/activate

echo "Installing package..."
pip install --upgrade pip
pip install -e .

mkdir -p cases captures logs
chmod +x launch.sh

echo
echo "Install complete."
echo "Run ./launch.sh for the default quickstart flow."
echo "Run 'spectre' for the interactive TUI, or 'spectre --advanced' for CLI access."
