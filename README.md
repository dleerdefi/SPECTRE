# SPECTRE

**S**pecial **P**urpose **E**lectronic **C**ounter-intelligence & **T**actical **R**econ **E**ngine

Wireless tactical assessment toolkit for authorized pentesting on Kali Linux. Passive surveys, automated capture campaigns, AI-powered vulnerability analysis, case tracking, and beginner-friendly onboarding — all in one CLI.

## Features

- **System readiness** — inspect adapters, tools, and provider availability
- **Passive surveys** — discover networks and clients via Kismet or airodump-ng
- **Capture orchestration** — PMKID and deauth-based handshake capture with auto-targeting
- **Automated campaigns** — `autopwn` chains survey, attack, and crack into a single workflow
- **Cracking** — hashcat integration for WPA/WPA2 (mode 22000) with hardware-tuned profiles
- **AI analysis** (optional) — LLM-powered vulnerability assessment via any OpenAI-compatible backend
- **Case management** — store evidence artifacts and generate reports
- **Interactive TUI** — SPECTRE menu-driven interface with numbered options
- **Beginner wizard** — guided quickstart for lab use and operator onboarding

## Prerequisites

### System Tools

Most are pre-installed on Kali. Run `spectre doctor` to check.

| Tool | Purpose | Install |
|------|---------|---------|
| aircrack-ng suite | Scanning, deauth, capture | `sudo apt install aircrack-ng` |
| iw | Adapter management | `sudo apt install iw` |
| kismet | Passive survey (preferred) | See [Kismet Setup](#kismet-setup) |
| hcxdumptool | PMKID/PSK capture pipeline | `sudo apt install hcxdumptool` |
| hcxpcapngtool | pcapng to hashcat conversion | `sudo apt install hcxtools` |
| tshark | Packet inspection, evidence validation | `sudo apt install tshark` |
| hashcat | WPA/WPA2 password cracking | `sudo apt install hashcat` |

### Hardware

A single monitor-mode-capable WiFi adapter is sufficient. SPECTRE works with one adapter (sequential scan then attack) or two (simultaneous operations if both support monitor mode).

**Recommended:**
- **ALFA AWUS036ACH** (RTL8812AU) — packet injection + deauth + monitor mode. Handles all operations.

**Not recommended:**
- **ALFA AWUS036AXML** (MT7921U) — broken injection in mt76 driver, degraded passive monitor (can't see associated clients). Kismet crashes with this adapter.

Run `spectre adapters` to see detected interfaces, capabilities, and auto-assigned roles.

**Single-adapter workflow:** When only one adapter is available, SPECTRE scans first, then attacks sequentially — the same approach used by wifite2 and most single-adapter tools.

### Kismet Setup

Kismet is the preferred survey provider but **not required** — SPECTRE falls back to airodump-ng automatically if Kismet is unavailable.

**Important:** The Kali apt package of Kismet has a [known SIGSEGV bug](docs/kismet-bug-fix.md) ([kismetwireless/kismet#602](https://github.com/kismetwireless/kismet/issues/602)) when using `--no-plugins`. You must build from source with the fix applied:

```bash
# Install build dependencies
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
  build-essential git libwebsockets-dev pkg-config zlib1g-dev \
  libnl-3-dev libnl-genl-3-dev libcap-dev libpcap-dev libnm-dev \
  libdw-dev libsqlite3-dev libsensors-dev libusb-1.0-0-dev \
  libprotobuf-c-dev protobuf-c-compiler librtlsdr-dev libmosquitto-dev

# Clone, patch, and build
cd /tmp
git clone https://github.com/kismetwireless/kismet.git kismet-src
cd kismet-src
sed -i 's/^\(\s*\)plugintracker->finalize_plugins();/\1if (plugintracker != nullptr)\n\1    plugintracker->finalize_plugins();/' kismet_server.cc
./configure && make -j$(nproc) && sudo make suidinstall

# Verify
kismet --version
```

SPECTRE auto-configures Kismet's httpd credentials on first run — no manual config needed.

If you prefer to skip Kismet entirely, airodump-ng works out of the box:
```bash
sudo apt install aircrack-ng
```

## Quick Start

### Automated install

```bash
git clone https://github.com/dleerdefi/spectre.git
cd spectre
./install.sh
source venv/bin/activate
```

### Manual install

```bash
git clone https://github.com/dleerdefi/spectre.git
cd spectre
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Get started

```bash
# (Optional) Download extended wordlists for cracking
python wordlists/download_wordlists.py

# Check system readiness
spectre doctor

# Launch the interactive TUI
spectre

# Or run a specific command directly
sudo $(which spectre) survey --duration 30
```

## Commands

### System

| Command | Description | Sudo? |
|---------|-------------|-------|
| `doctor` | Inspect all tools, providers, and adapter readiness | No |
| `preflight` | Run system validation checks | No |
| `adapters` | List WiFi adapters with capabilities | No |
| `monitor` | Enable monitor mode on an adapter | Yes |

### Operations

| Command | Description | Sudo? |
|---------|-------------|-------|
| `survey` | Passive survey via Kismet or airodump-ng | Yes |
| `scan` | Quick network discovery scan | Yes |
| `capture` | Manual handshake capture | Yes |
| `autopwn` | Automated campaign: survey -> attack -> crack | Yes |
| `quickcapture` | Automated scan -> capture workflow | Yes |
| `crack` | Crack WPA/WPA2 hashes with hashcat | No |
| `analyze` | AI-powered vulnerability analysis (optional) | No |

### Casework

| Command | Description |
|---------|-------------|
| `cases` | Create and manage case files |
| `report` | Generate a case summary report |

### Learning

| Command | Description |
|---------|-------------|
| `wizard` | Interactive beginner onboarding |
| `sandbox` | Safe mobile hotspot test environment |

### Wordlists

| Command | Description |
|---------|-------------|
| `wordlists list` | Show available wordlists by category |
| `wordlists generate` | Generate targeted wordlists |
| `wordlists import` | Import external wordlists |
| `wordlists stats` | Show wordlist statistics |

Use `spectre COMMAND --help` for detailed options.

### Survey Providers

The `survey` command supports multiple backends:

```bash
sudo $(which spectre) survey --provider auto      # Auto-select best available
sudo $(which spectre) survey --provider kismet     # Use Kismet
sudo $(which spectre) survey --provider native     # Use airodump-ng
```

When `--provider auto` (default), Kismet is preferred if installed. Falls back to native airodump-ng.

### Autopwn Campaigns

Fully automated attack chain: survey networks, analyze attack vectors, cycle through PMKID and deauth techniques per target, then crack captured handshakes.

```bash
sudo $(which spectre) autopwn --scan-time 90 --crack
sudo $(which spectre) autopwn --targets 1,3,5      # Attack specific targets
sudo $(which spectre) autopwn --targets all         # Attack all discovered networks
```

Press Ctrl+C once to skip a target, twice to abort the campaign.

## AI Analysis (Optional)

The `analyze` command sends survey data to a local LLM for automated vulnerability assessment. This is entirely optional — all other features work without it.

### Requirements

An OpenAI-compatible API server running locally or via SSH tunnel:

- [LM Studio](https://lmstudio.ai) (recommended)
- [Ollama](https://ollama.com)
- [vLLM](https://docs.vllm.ai)

### Setup

```bash
# Set the LLM endpoint (default: http://localhost:1234)
export LLM_URL=http://localhost:1234
export LLM_MODEL=your-model-name    # Auto-detected if omitted

# If your LLM runs on a remote machine, use an SSH tunnel:
ssh -N -L 1234:localhost:1234 user@llm-server
```

### Usage

```bash
# Analyze a live survey
sudo $(which spectre) analyze --duration 30

# Analyze saved scan data (no adapter needed)
spectre analyze --from-file scan_results.json

# JSON output for scripting
spectre analyze --from-file scan.json --json-output
```

The LLM identifies vulnerabilities (open networks, WEP, WPS, weak encryption), suggests attack vectors, and recommends fixes. In auto-attack mode (via TUI settings), it executes capture and crack commands directly.

SPECTRE's AI analysis approach was inspired by [METATRON](https://github.com/sooryathejas/METATRON) by Soorya Thejas.

## Database (Optional)

SPECTRE uses PostgreSQL with TimescaleDB for persistent logging of scan results, attack logs, and handshakes. The database is **optional** — all core features (survey, capture, crack, analyze) work without it.

### Quick setup

```bash
# Start the database (requires Docker)
docker compose up -d

# Copy and edit the env file
cp .env.example .env
# Edit .env and set DB_PASSWORD
```

### Remote database

If your database runs on a different machine:

```bash
# In .env:
DB_HOST=your-db-server
DB_PORT=5432
DB_USER=spectre
DB_PASSWORD=your-password
DB_NAME=spectre_db
```

The schema is applied automatically on first container startup via `db/init/001-schema.sql`.

## Configuration

All settings can be overridden via environment variables. Create a `.env` file in the project root for persistence.

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_URL` | `http://localhost:1234` | LLM API endpoint |
| `LLM_MODEL` | (auto-detected) | Model identifier |
| `LLM_MAX_TOKENS` | `8192` | Max tokens per LLM response |
| `LLM_TIMEOUT` | `600` | LLM request timeout (seconds) |
| `LLM_MAX_ROUNDS` | `9` | Max agentic tool-dispatch rounds |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `spectre_db` | Database name |
| `CAPTURE_DIR` | `captures/` | Handshake output directory |
| `WORDLIST_DIR` | `wordlists/` | Wordlist search path |

## Entry Points

```bash
spectre                            # Interactive TUI (default)
spectre --advanced                 # Show full command menu
spectre COMMAND --help             # Direct command access
```

Note: commands that touch WiFi hardware (survey, capture, monitor) require `sudo`. Use `sudo $(which spectre)` to run with the venv's Python.

## Project Layout

```text
src/
  wifi_launchpad/               # Internal package (rename planned)
    app/          Settings, paths, configuration
    cli/          Click commands, TUI, and display helpers
    domain/       Pure dataclasses (Network, Client, Handshake, etc.)
    prompts/      System prompts for LLM analysis (editable .txt files)
    providers/    External tool wrappers (Kismet, hashcat, hcx, aircrack)
    quickstart/   Beginner wizard workflow
    services/     Business logic orchestration
    storage/      Case artifact persistence

tests/            Test suite
docs/             Specs, design notes, and bug fixes
wordlists/        Default and custom wordlists
```

## Testing

```bash
source venv/bin/activate
python3 -m pytest -q
```

## Legal and Ethical Use

Use this project only for networks you own or are explicitly authorized to assess. It is intended for education, lab work, and professional authorized testing.

## License

[MIT](LICENSE)
