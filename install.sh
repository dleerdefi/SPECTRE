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

mkdir -p cases captures logs exports

echo
echo "Install complete."
echo
echo "  spectre              Launch the interactive TUI"
echo "  spectre --advanced   Show all CLI commands"
echo "  spectre doctor       Check system readiness"
echo
echo "(Optional) Set up the database for persistent logging:"
echo "  docker compose up -d"
echo "  cp .env.example .env  # then edit DB_PASSWORD"
echo
