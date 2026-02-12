"""Tests for configuration."""

import os
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from defuse_monitor.core.config import Config, DiscordConfig


def test_discord_config_valid_url():
    """Test that valid webhook URLs are accepted."""
    config = DiscordConfig(
        enabled=True,
        webhook_url="https://discord.com/api/webhooks/123/abc",
    )
    assert str(config.webhook_url) == "https://discord.com/api/webhooks/123/abc"


def test_discord_config_invalid_url():
    """Test that invalid webhook URLs are rejected."""
    with pytest.raises(ValidationError):
        DiscordConfig(enabled=True, webhook_url="not-a-url")


def test_discord_config_none_url():
    """Test that None webhook URL is accepted."""
    config = DiscordConfig(enabled=False, webhook_url=None)
    assert config.webhook_url is None


def test_config_load_valid():
    """Test loading a valid config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[monitoring]
auth_log_path = "/var/log/auth.log"

[deduplication]
enabled = true
window_seconds = 15

[defuse]
timeout_seconds = 30
artifact_directory = "/tmp/defuse"

[alerts]
enabled = true

[logging]
level = "DEBUG"
""")
        f.flush()
        tmp_path = f.name

    try:
        config = Config.load(Path(tmp_path))
        assert config.deduplication.window_seconds == 15
        assert config.defuse.timeout_seconds == 30
        assert config.logging.level == "DEBUG"
    finally:
        os.unlink(tmp_path)


def test_config_load_missing_file():
    """Test loading a non-existent config file."""
    with pytest.raises(FileNotFoundError):
        Config.load(Path("/nonexistent/config.toml"))


def test_config_defaults():
    """Test default configuration values."""
    config = Config()
    assert config.monitoring.auth_log_path == "/var/log/auth.log"
    assert config.deduplication.enabled is True
    assert config.defuse.timeout_seconds == 60
    assert config.alerts.enabled is True
