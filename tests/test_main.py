"""Tests for main module."""

import asyncio
import logging
from datetime import UTC, datetime

from defuse_monitor.__main__ import LogLevel, _create_monitor_tasks
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
