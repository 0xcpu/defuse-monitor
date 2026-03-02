"""Tests for main module."""

import asyncio
import logging
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from defuse_monitor.__main__ import (
    LogLevel,
    _create_login_event_handler,
    _create_monitor_tasks,
)
from defuse_monitor.core.config import AlertsConfig, Config
from defuse_monitor.core.dispatcher import EventDispatcher
from defuse_monitor.core.events import LoginEvent


def test_log_level_choices():
    """Test that LogLevel enum produces valid CLI choices."""
    choices = [level.value for level in LogLevel]
    assert choices == ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


async def test_monitor_wrapper_logs_warning_on_failure(caplog):
    """Test that monitor wrapper logs a warning when a monitor fails."""

    async def failing_monitor():
        raise RuntimeError("Simulated failure")
        yield  # make it an async generator

    dispatcher = EventDispatcher()
    monitors = [("test", failing_monitor())]

    with caplog.at_level(logging.WARNING):
        tasks = _create_monitor_tasks(monitors, dispatcher, None)

        # Wait for the task to finish (it should fail quickly)
        await asyncio.gather(*tasks, return_exceptions=True)

    assert any("Monitor test failed" in r.message for r in caplog.records)
    assert any(
        "Monitor test will not be restarted automatically" in r.message
        for r in caplog.records
    )


async def test_event_dispatcher_calls_handlers():
    """Test that dispatcher calls all registered handlers."""
    dispatcher = EventDispatcher()
    results = []

    async def handler1(event):
        results.append(("h1", event.username))

    async def handler2(event):
        results.append(("h2", event.username))

    dispatcher.register_handler(handler1)
    dispatcher.register_handler(handler2)

    event = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="test",
    )
    await dispatcher.dispatch(event)

    assert ("h1", "alice") in results
    assert ("h2", "alice") in results


async def test_event_dispatcher_no_handlers():
    """Test dispatcher with no handlers does not error."""
    dispatcher = EventDispatcher()
    event = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="test",
    )
    await dispatcher.dispatch(event)  # Should not raise


def make_event(login_type: str) -> LoginEvent:
    return LoginEvent(
        username="ubuntu",
        source_ip=None,
        login_type=login_type,
        timestamp=datetime.now(),
        monitor_source="auth_log",
    )


def make_config(ignored_login_types: list[str]) -> Config:
    config = Config()
    config.alerts = AlertsConfig(ignored_login_types=ignored_login_types)
    return config


@pytest.mark.asyncio
async def test_ignored_login_type_does_not_alert():
    config = make_config(["console", "other"])
    defuse_handler = MagicMock()
    defuse_handler.initiate_defuse = AsyncMock(return_value=False)
    alert_dispatcher = MagicMock()
    alert_dispatcher.send_alert = AsyncMock()

    handler = _create_login_event_handler(defuse_handler, alert_dispatcher, config)
    await handler(make_event("other"))

    alert_dispatcher.send_alert.assert_not_called()
    defuse_handler.initiate_defuse.assert_not_called()


@pytest.mark.asyncio
async def test_non_ignored_login_type_does_alert():
    config = make_config(["console", "other"])
    defuse_handler = MagicMock()
    defuse_handler.initiate_defuse = AsyncMock(return_value=False)
    alert_dispatcher = MagicMock()
    alert_dispatcher.send_alert = AsyncMock()

    handler = _create_login_event_handler(defuse_handler, alert_dispatcher, config)
    await handler(make_event("ssh"))

    alert_dispatcher.send_alert.assert_called_once()


@pytest.mark.asyncio
async def test_empty_ignored_list_alerts_everything():
    config = make_config([])
    defuse_handler = MagicMock()
    defuse_handler.initiate_defuse = AsyncMock(return_value=False)
    alert_dispatcher = MagicMock()
    alert_dispatcher.send_alert = AsyncMock()

    handler = _create_login_event_handler(defuse_handler, alert_dispatcher, config)
    await handler(make_event("console"))

    alert_dispatcher.send_alert.assert_called_once()


@pytest.mark.asyncio
async def test_alerts_disabled_does_not_alert():
    """When alerts are globally disabled, send_alert must not be called."""
    config = make_config([])
    config.alerts.enabled = False
    defuse_handler = MagicMock()
    defuse_handler.initiate_defuse = AsyncMock(return_value=False)
    alert_dispatcher = MagicMock()
    alert_dispatcher.send_alert = AsyncMock()

    handler = _create_login_event_handler(defuse_handler, alert_dispatcher, config)
    await handler(make_event("ssh"))

    alert_dispatcher.send_alert.assert_not_called()


@pytest.mark.asyncio
async def test_defuse_success_does_not_alert():
    """When the defuse handler returns True (defused), send_alert must not be called."""
    config = make_config([])
    defuse_handler = MagicMock()
    defuse_handler.initiate_defuse = AsyncMock(return_value=True)
    alert_dispatcher = MagicMock()
    alert_dispatcher.send_alert = AsyncMock()

    handler = _create_login_event_handler(defuse_handler, alert_dispatcher, config)
    await handler(make_event("ssh"))

    alert_dispatcher.send_alert.assert_not_called()
