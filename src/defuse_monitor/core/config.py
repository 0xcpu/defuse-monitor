"""Configuration handling for defuse monitor."""

from pathlib import Path

import toml
from pydantic import BaseModel, ConfigDict, HttpUrl, field_validator, model_validator


class MonitoringConfig(BaseModel):
    """Configuration for monitoring sources."""

    model_config = ConfigDict(extra="forbid")

    auth_log_path: str = "/var/log/auth.log"
    wtmp_path: str = "/var/log/wtmp"
    btmp_path: str = "/var/log/btmp"
    utmp_path: str = "/var/run/utmp"


class DeduplicationConfig(BaseModel):
    """Configuration for event deduplication."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    window_seconds: int = 10


class DefuseConfig(BaseModel):
    """Configuration for defuse mechanism."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: int = 60
    artifact_directory: str = "/var/run/defuse"
    require_signature: bool = False
    secret: str | None = None


class DiscordConfig(BaseModel):
    """Discord webhook alert configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    webhook_url: HttpUrl | None = None

    @model_validator(mode="after")
    def _validate_webhook_url(self) -> "DiscordConfig":
        if self.enabled and self.webhook_url is None:
            raise ValueError("webhook_url is required when Discord alerts are enabled")
        return self


class AlertsConfig(BaseModel):
    """Alert system configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    rate_limit_per_hour: int = 10
    ignored_login_types: list[str] = []
    discord: DiscordConfig = DiscordConfig()


class LoggingConfig(BaseModel):
    """Logging configuration."""

    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"
    file: str = "/var/log/defuse/monitor.log"
    max_size_mb: int = 100
    backup_count: int = 5

    @field_validator("level")
    @classmethod
    def _validate_level(cls, v: str) -> str:
        normalized = v.upper()
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in valid:
            raise ValueError(
                f"Invalid logging level: {v!r}. Must be one of {sorted(valid)}"
            )
        return normalized


class Config(BaseModel):
    """Main configuration class."""

    model_config = ConfigDict(extra="forbid")

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
