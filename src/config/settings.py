"""
Application configuration management using Pydantic Settings
"""

from pathlib import Path
from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application
    app_name: str = Field(default="WiFi-Launchpad", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    debug: bool = Field(default=False, env="DEBUG")
    
    # Database
    db_host: str = Field(env="DB_HOST")
    db_port: int = Field(default=5432, env="DB_PORT")
    db_name: str = Field(env="DB_NAME")
    db_user: str = Field(env="DB_USER")
    db_password: str = Field(env="DB_PASSWORD")
    db_pool_size: int = Field(default=20, env="DB_POOL_SIZE")
    
    # Redis
    redis_host: str = Field(env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_db: int = Field(default=0, env="REDIS_DB")
    
    # Network Adapters
    monitor_interface: str = Field(default="wlan0", env="MONITOR_INTERFACE")
    injection_interface: str = Field(default="wlan2mon", env="INJECTION_INTERFACE")
    management_interface: Optional[str] = Field(default="wlan1", env="MANAGEMENT_INTERFACE")
    
    # GPU Server
    gpu_server_enabled: bool = Field(default=False, env="GPU_SERVER_ENABLED")
    gpu_server_host: Optional[str] = Field(default=None, env="GPU_SERVER_HOST")
    gpu_server_user: Optional[str] = Field(default=None, env="GPU_SERVER_USER")
    gpu_server_key_path: Optional[Path] = Field(default=None, env="GPU_SERVER_KEY_PATH")
    
    # File Paths
    wordlist_dir: Path = Field(default=Path("/opt/wifi-launchpad/wordlists"), env="WORDLIST_DIR")
    capture_dir: Path = Field(default=Path("/opt/wifi-launchpad/captures"), env="CAPTURE_DIR")
    log_dir: Path = Field(default=Path("/var/log/wifi-launchpad"), env="LOG_DIR")
    temp_dir: Path = Field(default=Path("/tmp/wifi-launchpad"), env="TEMP_DIR")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=4, env="API_WORKERS")
    
    # Security
    api_key: Optional[str] = Field(default=None, env="API_KEY")
    secret_key: str = Field(env="SECRET_KEY")
    
    # Feature Flags
    enable_sandbox_mode: bool = Field(default=True, env="ENABLE_SANDBOX_MODE")
    enable_auto_updates: bool = Field(default=True, env="ENABLE_AUTO_UPDATES")
    enable_telemetry: bool = Field(default=False, env="ENABLE_TELEMETRY")
    
    # Performance
    max_concurrent_scans: int = Field(default=3, env="MAX_CONCURRENT_SCANS")
    scan_channel_hop_interval: float = Field(default=0.5, env="SCAN_CHANNEL_HOP_INTERVAL")
    handshake_timeout: int = Field(default=300, env="HANDSHAKE_TIMEOUT")
    deauth_burst_count: int = Field(default=10, env="DEAUTH_BURST_COUNT")
    deauth_burst_delay: float = Field(default=0.1, env="DEAUTH_BURST_DELAY")
    
    @validator("wordlist_dir", "capture_dir", "log_dir", "temp_dir")
    def create_directories(cls, v: Path) -> Path:
        """Ensure directories exist"""
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    @property
    def database_url(self) -> str:
        """Construct database URL"""
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
    
    @property
    def redis_url(self) -> str:
        """Construct Redis URL"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


# Global settings instance
settings = Settings()


# Configuration loader for YAML files
import yaml
from typing import Dict, Any


def load_yaml_config(config_file: Path) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


def load_adapters_config() -> Dict[str, Any]:
    """Load adapter configuration"""
    config_path = Path(__file__).parent.parent.parent / "config" / "adapters.yaml"
    return load_yaml_config(config_path)


def load_targets_config() -> Dict[str, Any]:
    """Load target configuration"""
    config_path = Path(__file__).parent.parent.parent / "config" / "targets.yaml"
    return load_yaml_config(config_path)