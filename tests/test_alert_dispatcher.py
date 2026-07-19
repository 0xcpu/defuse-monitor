"""Tests for alert dispatcher."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

from defuse_monitor.alerts.dispatcher import AlertDispatcher
from defuse_monitor.core.events import LoginEvent


async def test_alert_dispatcher_reuses_session():
    """Test that AlertDispatcher reuses the aiohttp session."""
    dispatcher = AlertDispatcher(
        discord_enabled=True,
        webhook_url="https://discord.com/api/webhooks/test/test",
    )

    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.close = AsyncMock()

        mock_response = AsyncMock()
        mock_response.status = 204

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_response
        mock_ctx.__aexit__.return_value = False
        mock_session.post.return_value = mock_ctx

        mock_session_cls.return_value = mock_session

        await dispatcher.send_discord_webhook("test message 1")
        await dispatcher.send_discord_webhook("test message 2")

        # Session should be created only once
        assert mock_session_cls.call_count == 1

    await dispatcher.close()


def _make_response_ctx(status: int, text: str = ""):
    """Build a mock async context manager for a webhook response."""
    mock_response = AsyncMock()
    mock_response.status = status
    mock_response.text.return_value = text

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_response
    mock_ctx.__aexit__.return_value = False
    return mock_ctx


async def test_discord_webhook_retries_then_succeeds():
    """Test that a transient failure is retried and eventually succeeds."""
    dispatcher = AlertDispatcher(
        discord_enabled=True,
        webhook_url="https://discord.com/api/webhooks/test/test",
    )

    with (
        patch("aiohttp.ClientSession") as mock_session_cls,
        patch("asyncio.sleep", new=AsyncMock()) as mock_sleep,
    ):
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.close = AsyncMock()
        mock_session.post.side_effect = [
            _make_response_ctx(429, "rate limited"),
            _make_response_ctx(204),
        ]
        mock_session_cls.return_value = mock_session

        await dispatcher.send_discord_webhook("test message")

        assert mock_session.post.call_count == 2
        assert mock_sleep.await_count == 1

    await dispatcher.close()


async def test_discord_webhook_exhausts_retries():
    """Test that repeated failures exhaust retries without raising."""
    dispatcher = AlertDispatcher(
        discord_enabled=True,
        webhook_url="https://discord.com/api/webhooks/test/test",
    )

    with (
        patch("aiohttp.ClientSession") as mock_session_cls,
        patch("asyncio.sleep", new=AsyncMock()) as mock_sleep,
    ):
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.close = AsyncMock()
        mock_session.post.side_effect = aiohttp.ClientError("boom")
        mock_session_cls.return_value = mock_session

        await dispatcher.send_discord_webhook("test message")

        assert mock_session.post.call_count == 3
        assert mock_sleep.await_count == 2

    await dispatcher.close()


def test_alert_format_message():
    """Test alert message formatting."""
    dispatcher = AlertDispatcher()
    event = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        monitor_source="auth_log",
    )

    message = dispatcher._format_alert_message(event)

    assert "alice" in message
    assert "ssh" in message
    assert "192.168.1.100" in message


def test_alert_format_message_local():
    """Test alert message formatting for local login."""
    dispatcher = AlertDispatcher()
    event = LoginEvent(
        username="bob",
        login_type="console",
        timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        monitor_source="auth_log",
    )

    message = dispatcher._format_alert_message(event)

    assert "bob" in message
    assert "local" in message
