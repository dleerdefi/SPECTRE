# SPECTRE

**S**pecial **P**urpose **E**lectronic **C**ounter-intelligence & **T**actical **R**econ **E**ngine

Wireless tactical assessment toolkit for authorized pentesting on Kali Linux. Multi-tool surveys, automated attack campaigns with WPS escalation, AI-powered vulnerability analysis with evidence-gating, TimescaleDB persistence, and beginner-friendly onboarding — all in one CLI.

## Features

- **Multi-tool surveys** — Kismet + wash + airodump-ng + tshark pipeline, each contributing its strongest capability
- **WPS attack escalation** — pixie dust, Reaver PIN brute, Bully fallback (bypasses PMF-protected networks)
- **5-step attack chain** — PMKID, deauth (3 strategies), pixie dust WPS with intelligent target scoring
- **Handshake validation** — EAPOL pair verified via hcxpcapngtool before declaring capture success
- **User approval gates** — GPU cracking and long-running WPS brute force require explicit approval
- **AI analysis** (optional) — evidence-gated LLM assessment with confidence levels and self-review
- **Correction tracking** — paste-based import of external LLM reviews, corrections persist to DB
- **TimescaleDB persistence** — time-series storage with MAC hashing, retention policies, and compression
- **Capture orchestration** — PMKID and deauth-based handshake capture with auto-targeting
- **Cracking** — hashcat integration for WPA/WPA2 (mode 22000) with hardware-tuned profiles
- **Case management** — store evidence artifacts and generate reports
- **Interactive TUI** — configurable settings for provider, signal threshold, attack timeout
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
| tshark | Packet inspection, traffic analysis | `sudo apt install tshark` |
| hashcat | WPA/WPA2 password cracking | `sudo apt install hashcat` |
| wash | WPS AP detection | `sudo apt install reaver` |
| reaver | WPS pixie dust + PIN brute force | `sudo apt install reaver` |
| bully | WPS brute force (Reaver fallback) | `sudo apt install bully` |

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

**Note:** The Kali apt package of Kismet had a [SIGSEGV bug](docs/kismet-bug-fix.md) ([kismetwireless/kismet#602](https://github.com/kismetwireless/kismet/issues/602)) when using `--no-plugins`. This has been **fixed upstream.** If your Kali package still crashes, build from source until Kali updates their package:

```bash
# Install build dependencies
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
  build-essential git libwebsockets-dev pkg-config zlib1g-dev \
  libnl-3-dev libnl-genl-3-dev libcap-dev libpcap-dev libnm-dev \
  libdw-dev libsqlite3-dev libsensors-dev libusb-1.0-0-dev \
  libprotobuf-c-dev protobuf-c-compiler librtlsdr-dev libmosquitto-dev

# Clone and build (fix is now in upstream main)
cd /tmp
git clone https://github.com/kismetwireless/kismet.git kismet-src
cd kismet-src
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
pip install -e ".[all]"    # includes DB + search dependencies
# Or minimal: pip install -e .
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

Fully automated attack chain with multi-tool survey and intelligent escalation.

**Survey pipeline** (with `--provider auto`):
1. Kismet passive recon (device fingerprinting, protocol classification)
2. wash WPS scan (detect WPS-enabled APs, lock status)
3. airodump-ng client pass (active station tracking, probe requests)
4. tshark traffic analysis (protocol fingerprinting, cleartext detection)

**Attack escalation** (per target, sequential):
1. PMKID probe (clientless, 30s)
2. Deauth broadcast (60s)
3. Deauth per-client (60s)
4. Deauth aggressive (90s)
5. Pixie dust WPS — bypasses PMF (60s, if WPS detected)

**Target scoring** prioritizes by signal strength, connected clients, WPS status, and encryption weakness. Targets below the signal threshold are skipped.

```bash
# Standard campaign
sudo $(which spectre) autopwn --scan-time 90 --crack

# Multi-tool pipeline
sudo $(which spectre) autopwn --scan-time 90 --provider auto

# Custom signal threshold (default: -70, lower = more targets)
sudo $(which spectre) autopwn --min-signal -85

# Per-target capture timeout
sudo $(which spectre) autopwn --attack-timeout 180

# Target selection
sudo $(which spectre) autopwn --targets 1,3,5
sudo $(which spectre) autopwn --targets all
```

Press Ctrl+C once to skip a target, twice to abort the campaign.

## AI Analysis (Optional)

The `analyze` command sends survey data to a local LLM for automated vulnerability assessment. This is entirely optional — all other features work without it.

### Evidence-Gated Analysis

The LLM operates with a skeptical pentester mindset:
- **Default assumption: NOT vulnerable** — evidence required to override
- Every finding must quote specific scan output as **evidence**
- Each finding gets a **confidence level**: confirmed, likely, or possible
- Recommendations are separated from vulnerabilities (no padding the vuln count)
- Platform awareness: ISP hotspots, enterprise networks, home routers handled differently

After analysis, a **self-review pass** audits each finding against 7 checks: evidence gate, network identity, encryption accuracy, severity proportionality, confidence accuracy, platform awareness, and recommendation validity.

### AI-Driven Attacks

In auto-attack mode (TUI Settings), the LLM can command attack tools:
- `[TOOL: capture --bssid XX:XX --channel N]` — handshake capture
- `[TOOL: pixie --bssid XX:XX]` — WPS pixie dust attack
- `[TOOL: reaver --bssid XX:XX]` — WPS PIN brute (requires approval)
- `[TOOL: bully --bssid XX:XX]` — WPS fallback (requires approval)
- `[TOOL: validate --file capture.pcapng]` — handshake verification
- `[TOOL: crack --file hash.22000]` — cracking (requires approval)

### Correction Workflow

1. Run analysis, results saved to DB
2. Export findings to markdown (TUI option [4])
3. Paste into Claude Code or another LLM for review
4. Import corrections via paste (TUI option [5]) — select which analysis to correct
5. Corrections persist to DB and feed into future analysis prompts via learned rules

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

SPECTRE's AI analysis approach was inspired by [METATRON](https://github.com/sooryathejas/METATRON) by Soorya Thejas.

## Database (Optional)

SPECTRE uses PostgreSQL with TimescaleDB for persistent storage. The database is **optional** — all core features work without it.

### What TimescaleDB provides

Time-series data (beacons, client observations, attack events) is stored in **hypertables** — regular PostgreSQL tables that are automatically partitioned by time. This keeps queries fast as data grows and enables automatic lifecycle management.

| Hypertable | Data | Retention |
|------------|------|-----------|
| `networks` | Beacon observations per AP | 365 days |
| `clients` | Client associations + probes (MAC-hashed) | 90 days |
| `security_events` | Detections + anomalies | 180 days |
| `attack_logs` | Attack attempts + results | 365 days |
| `traffic_observations` | Protocol/cleartext findings from tshark | 90 days |

Regular tables (not time-series):
- `analysis_results` — LLM analysis runs
- `analysis_vulnerabilities` — parsed findings with confidence + evidence
- `analysis_corrections` — external review corrections
- `wifi_learned_rules` — distilled rules from correction reviews
- `handshakes` — captured handshake artifacts (kept indefinitely)

**Privacy:** Client MAC addresses are stored as SHA-256 hashes, never in plaintext.

### Quick setup

```bash
# Start the database (requires Docker)
docker compose up -d

# Copy and edit the env file
cp .env.example .env
# Edit .env and set DB_PASSWORD

# Install the DB dependency
pip install -e ".[db]"
```

Schema is applied automatically on first container startup via `db/init/*.sql` (3 migration files).

### Remote database

If your database runs on a different machine:

```bash
# In .env:
DB_HOST=your-db-server
DB_PORT=5432
DB_USER=spectre
DB_PASSWORD=your-password
DB_NAME=spectre_db
COLLECTOR_NODE=local    # identifies this host in multi-node deployments
```

## TUI Settings

### Attack Campaign Settings

```
[1] Survey provider     [auto]          — auto, kismet, or native
[2] Min signal strength [-70 dBm]       — lower values include weaker targets
[3] Attack timeout      [120s]          — per-target capture window
[4] Auto-crack          [ON]            — prompt for cracking after capture
```

### AI Analysis Settings

```
[1] Toggle auto-attack mode  (OFF)      — LLM executes capture/crack commands
[2] Set max rounds  (default 9)         — agentic tool-dispatch rounds
[3] Toggle auto-export  (OFF)           — auto-export after analysis
[4] Survey provider  (auto)             — for live analysis scans
```

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
| `DB_CONNECT_TIMEOUT` | `5` | DB connection timeout (seconds) |
| `COLLECTOR_NODE` | `local` | Node identifier for multi-collector deployments |
| `CAPTURE_DIR` | `captures/` | Handshake output directory |
| `WORDLIST_DIR` | `wordlists/` | Wordlist search path |

### Optional Python Dependencies

```bash
pip install -e ".[all]"     # Database + LLM search
pip install -e ".[db]"      # Database only (psycopg)
pip install -e ".[search]"  # DuckDuckGo search only
```

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
    providers/    External tool wrappers (Kismet, hashcat, hcx, wash, reaver, bully)
    quickstart/   Beginner wizard workflow
    services/     Business logic (survey pipeline, attack planner, analysis, DB)
    storage/      Case artifact persistence

db/init/          SQL schema and migrations (TimescaleDB)
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
