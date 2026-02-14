"""Configuration handling for defuse monitor."""

from pathlib import Path

import toml
from pydantic import BaseModel, HttpUrl


class MonitoringConfig(BaseModel):
    """Configuration for monitoring sources."""

    auth_log_path: str = "/var/log/auth.log"
    wtmp_path: str = "/var/log/wtmp"
    btmp_path: str = "/var/log/btmp"
    utmp_path: str = "/var/run/utmp"


class DeduplicationConfig(BaseModel):
    """Configuration for event deduplication."""

    enabled: bool = True
    window_seconds: int = 10


class DefuseConfig(BaseModel):
    """Configuration for defuse mechanism."""

    timeout_seconds: int = 60
    artifact_directory: str = "/var/run/defuse"
    require_signature: bool = False


class DiscordConfig(BaseModel):
    """Discord webhook alert configuration."""

    enabled: bool = False
    webhook_url: HttpUrl | None = None


class AlertsConfig(BaseModel):
    """Alert system configuration."""

    enabled: bool = True
    rate_limit_per_hour: int = 10
    discord: DiscordConfig = DiscordConfig()


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    file: str = "/var/log/defuse/monitor.log"
    max_size_mb: int = 100
    backup_count: int = 5


class Config(BaseModel):
    """Main configuration class."""

    monitoring: MonitoringConfig = MonitoringConfig()
    deduplication: DeduplicationConfig = DeduplicationConfig()
    defuse: DefuseConfig = DefuseConfig()
    alerts: AlertsConfig = AlertsConfig()
    logging: LoggingConfig = LoggingConfig()

    @classmethod
    def load(cls, config_path: Path) -> "Config":
        """Load configuration from TOML file."""
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path) as f:
            data = toml.load(f)

        return cls(**data)
