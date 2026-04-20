"""Lightweight settings layer for the packaged runtime."""

from dataclasses import dataclass, field
from functools import lru_cache
import os
from pathlib import Path
from typing import List

from .paths import CAPTURE_ROOT, CASE_ROOT, CONFIG_ROOT, DOCS_ROOT, LOG_ROOT, PROJECT_ROOT, TEMP_ROOT, WORDLIST_ROOT

WORDLIST_CATEGORIES = [
    "default-passwords",
    "targeted",
    "generated",
    "isp-specific",
]

WORDLIST_IMPORT_CATEGORY_MAP = {
    "default": "default-passwords",
    "default-passwords": "default-passwords",
    "targeted": "targeted",
    "custom": "generated",
    "generated": "generated",
    "isp-specific": "isp-specific",
}


# ── Domain sub-configs ──────────────────────────────────────────────────


@dataclass(frozen=True)
class DbConfig:
    """Database connection parameters."""

    host: str = ""
    port: int = 5432
    dbname: str = "wifi_db"
    user: str = ""
    password: str = ""
    connect_timeout: int = 5
    collector_node: str = "local"  # identifies this host in multi-node deployments


@dataclass(frozen=True)
class CaptureDefaults:
    """Default tuning values for handshake capture."""

    timeout: int = 300
    write_interval: int = 2
    deauth_count: int = 5
    deauth_interval: int = 10
    min_quality_score: float = 60.0
    deauth_packet_count: int = 10
    deauth_burst_count: int = 5
    deauth_burst_interval: float = 5.0
    deauth_cooldown: float = 10.0


@dataclass(frozen=True)
class ScanDefaults:
    """Default tuning values for wireless scanning."""

    channel_dwell_time: float = 2.0
    write_interval: int = 5
    default_channels: List[int] = field(
        default_factory=lambda: [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
    )


@dataclass(frozen=True)
class CrackDefaults:
    """Default tuning values for cracking."""

    timeout: int = 600
    timeout_per_file: int = 300
    remote_host: str = ""
    remote_hashcat: str = "hashcat"
    remote_temp_dir: str = "/tmp/spectre-crack"


@dataclass(frozen=True)
class AttackDefaults:
    """Default technique timeouts for the attack chain."""

    pmkid_timeout: int = 30
    deauth_broadcast_timeout: int = 60
    deauth_targeted_timeout: int = 60
    deauth_aggressive_timeout: int = 90
    evil_portal_timeout: int = 300


@dataclass(frozen=True)
class EvilPortalDefaults:
    """Evil portal deployment defaults."""

    enabled: bool = False  # opt-in for attack chain
    timeout: int = 300
    template: str = "wifi-default"
    gateway_ip: str = "192.169.254.1"
    dhcp_range_start: str = "192.169.254.50"
    dhcp_range_end: str = "192.169.254.200"
    subnet_mask: str = "255.255.255.0"
    deauth_continuous: bool = True
    deauth_burst_count: int = 100
    deauth_burst_interval: float = 7.0
    use_mana: bool = False
    validate_psk: bool = True
    whitelist_after_capture: bool = True
    use_dhcp_option_114: bool = True


@dataclass(frozen=True)
class LLMConfig:
    """Optional LLM backend for AI-powered analysis.

    Requires an OpenAI-compatible API server (e.g. LM Studio, Ollama, vLLM).
    Analysis features are disabled when no server is reachable.

    Inspired by METATRON (https://github.com/sooryathejas/METATRON).
    """

    url: str = "http://localhost:1234"
    model: str = ""
    max_tokens: int = 8192
    timeout: int = 600
    max_rounds: int = 9


# ── Main settings ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class AppSettings:
    """Runtime paths and operator-facing defaults."""

    # Path fields (backward-compatible — existing consumers use these directly)
    project_root: Path = field(default=PROJECT_ROOT)
    docs_root: Path = field(default=DOCS_ROOT)
    config_root: Path = field(default=CONFIG_ROOT)
    wordlist_dir: Path = field(default=WORDLIST_ROOT)
    case_dir: Path = field(default=CASE_ROOT)
    capture_dir: Path = field(default=CAPTURE_ROOT)
    log_dir: Path = field(default=LOG_ROOT)
    temp_dir: Path = field(default=TEMP_ROOT)

    # Derived paths
    crack_dir: Path = field(default=TEMP_ROOT / "crack")
    oui_cache_file: Path = field(default=TEMP_ROOT / "oui_cache.json")

    # Domain sub-configs
    db: DbConfig = field(default_factory=DbConfig)
    capture: CaptureDefaults = field(default_factory=CaptureDefaults)
    scan: ScanDefaults = field(default_factory=ScanDefaults)
    crack: CrackDefaults = field(default_factory=CrackDefaults)
    attack: AttackDefaults = field(default_factory=AttackDefaults)
    evil_portal: EvilPortalDefaults = field(default_factory=EvilPortalDefaults)
    llm: LLMConfig = field(default_factory=LLMConfig)


def _int(val: str, default: int) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _float(val: str, default: float) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _parse_channels(val: str, default: List[int]) -> List[int]:
    """Parse comma-separated channel list from env."""
    if not val:
        return default
    try:
        return [int(ch.strip()) for ch in val.split(",") if ch.strip()]
    except ValueError:
        return default


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Build a cached settings object from environment-aware defaults."""
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
    except ImportError:
        pass

    temp_dir = Path(os.getenv("TEMP_DIR", str(TEMP_ROOT)))
    capture_dir = Path(os.getenv("CAPTURE_DIR", str(CAPTURE_ROOT)))

    return AppSettings(
        project_root=PROJECT_ROOT,
        docs_root=DOCS_ROOT,
        config_root=CONFIG_ROOT,
        wordlist_dir=Path(os.getenv("WORDLIST_DIR", str(WORDLIST_ROOT))),
        case_dir=Path(os.getenv("CASE_DIR", str(CASE_ROOT))),
        capture_dir=capture_dir,
        log_dir=Path(os.getenv("LOG_DIR", str(LOG_ROOT))),
        temp_dir=temp_dir,
        crack_dir=Path(os.getenv("CRACK_DIR", str(temp_dir / "crack"))),
        oui_cache_file=Path(os.getenv("OUI_CACHE_FILE", str(temp_dir / "oui_cache.json"))),
        db=DbConfig(
            host=os.getenv("DB_HOST", "localhost"),
            port=_int(os.getenv("DB_PORT", ""), 5432),
            dbname=os.getenv("DB_NAME", "spectre_db"),
            user=os.getenv("DB_USER", "spectre"),
            password=os.getenv("DB_PASSWORD", ""),
            connect_timeout=_int(os.getenv("DB_CONNECT_TIMEOUT", ""), 5),
            collector_node=os.getenv("COLLECTOR_NODE", "local"),
        ),
        capture=CaptureDefaults(
            timeout=_int(os.getenv("HANDSHAKE_TIMEOUT", ""), 300),
            write_interval=_int(os.getenv("CAPTURE_WRITE_INTERVAL", ""), 2),
            deauth_count=_int(os.getenv("DEAUTH_COUNT", ""), 5),
            deauth_interval=_int(os.getenv("DEAUTH_INTERVAL", ""), 10),
            min_quality_score=_float(os.getenv("MIN_QUALITY_SCORE", ""), 60.0),
            deauth_packet_count=_int(os.getenv("DEAUTH_PACKET_COUNT", ""), 10),
            deauth_burst_count=_int(os.getenv("DEAUTH_BURST_COUNT", ""), 5),
            deauth_burst_interval=_float(os.getenv("DEAUTH_BURST_INTERVAL", ""), 5.0),
            deauth_cooldown=_float(os.getenv("DEAUTH_COOLDOWN", ""), 10.0),
        ),
        scan=ScanDefaults(
            channel_dwell_time=_float(os.getenv("SCAN_CHANNEL_HOP_INTERVAL", ""), 2.0),
            write_interval=_int(os.getenv("SCAN_WRITE_INTERVAL", ""), 5),
            default_channels=_parse_channels(
                os.getenv("SCAN_CHANNELS", ""),
                [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161],
            ),
        ),
        crack=CrackDefaults(
            timeout=_int(os.getenv("CRACK_TIMEOUT", ""), 600),
            timeout_per_file=_int(os.getenv("CRACK_TIMEOUT_PER_FILE", ""), 300),
            remote_host=os.getenv("CRACK_HOST", ""),
            remote_hashcat=os.getenv("CRACK_REMOTE_HASHCAT", "hashcat"),
            remote_temp_dir=os.getenv("CRACK_REMOTE_TEMP_DIR", "/tmp/spectre-crack"),
        ),
        attack=AttackDefaults(
            pmkid_timeout=_int(os.getenv("PMKID_TIMEOUT", ""), 30),
            deauth_broadcast_timeout=_int(os.getenv("DEAUTH_BROADCAST_TIMEOUT", ""), 60),
            deauth_targeted_timeout=_int(os.getenv("DEAUTH_TARGETED_TIMEOUT", ""), 60),
            deauth_aggressive_timeout=_int(os.getenv("DEAUTH_AGGRESSIVE_TIMEOUT", ""), 90),
            evil_portal_timeout=_int(os.getenv("EVIL_PORTAL_TIMEOUT", ""), 300),
        ),
        evil_portal=EvilPortalDefaults(
            enabled=os.getenv("EVIL_PORTAL_ENABLED", "false").lower() == "true",
            timeout=_int(os.getenv("EVIL_PORTAL_TIMEOUT", ""), 300),
            template=os.getenv("EVIL_PORTAL_TEMPLATE", "wifi-default"),
            gateway_ip=os.getenv("EVIL_PORTAL_GATEWAY", "192.169.254.1"),
            use_mana=os.getenv("EVIL_PORTAL_MANA", "false").lower() == "true",
            validate_psk=os.getenv("EVIL_PORTAL_VALIDATE_PSK", "true").lower() == "true",
        ),
        llm=LLMConfig(
            url=os.getenv("LLM_URL", "http://localhost:1234"),
            model=os.getenv("LLM_MODEL", ""),
            max_tokens=_int(os.getenv("LLM_MAX_TOKENS", ""), 8192),
            timeout=_int(os.getenv("LLM_TIMEOUT", ""), 600),
            max_rounds=_int(os.getenv("LLM_MAX_ROUNDS", ""), 9),
        ),
    )
