"""Tests for event deduplication."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from defuse_monitor.core.deduplicator import EventDeduplicator
from defuse_monitor.core.events import LoginEvent


@pytest.fixture
def deduplicator():
    """Create a deduplicator instance with default settings."""
    return EventDeduplicator(window_seconds=10)


@pytest.fixture
def sample_event():
    """Create a sample login event."""
    return LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="auth_log",
    )


async def test_deduplicator_unique_event(deduplicator, sample_event):
    """Test that unique events are passed through."""
    result = await deduplicator.process_event(sample_event)

    assert result is not None
    assert result.username == "alice"
    assert result.monitor_source == "auth_log"
    assert result.detected_by == ["auth_log"]


async def test_deduplicator_duplicate_event(deduplicator):
    """Test that duplicate events are filtered out."""
    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="auth_log",
    )

    # Same event from different monitor
    event2 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=event1.timestamp,
        monitor_source="wtmp",
    )

    # First event should pass through
    result1 = await deduplicator.process_event(event1)
    assert result1 is not None
    assert result1.detected_by == ["auth_log"]

    # Second event should be filtered as duplicate
    result2 = await deduplicator.process_event(event2)
    assert result2 is None


async def test_deduplicator_enrichment(deduplicator):
    """Test that duplicate events enrich the existing event."""
    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="auth_log",
    )

    event2 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=event1.timestamp,
        monitor_source="wtmp",
        session_id="12345",  # Additional data
    )

    # Process first event
    result1 = await deduplicator.process_event(event1)
    assert result1 is not None

    # Process second event (duplicate)
    result2 = await deduplicator.process_event(event2)
    assert result2 is None

    # Check that the first event in cache was enriched
    assert len(deduplicator.recent_events) == 1
    cached_event, _ = deduplicator.recent_events[0]
    assert cached_event.detected_by == ["auth_log", "wtmp"]
    assert cached_event.session_id == "12345"  # Enriched with new data


async def test_deduplicator_different_users(deduplicator):
    """Test that events from different users are not deduplicated."""
    timestamp = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
    )

    event2 = LoginEvent(
        username="bob",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
    )

    # Both events should pass through
    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is not None
    assert result1.username == "alice"
    assert result2.username == "bob"


async def test_deduplicator_different_source_ips(deduplicator):
    """Test that events with different source IPs are not deduplicated."""
    timestamp = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
    )

    event2 = LoginEvent(
        username="alice",
        source_ip="192.168.1.200",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
    )

    # Both events should pass through (different source IPs)
    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is not None


async def test_deduplicator_time_window(deduplicator):
    """Test that events outside the time window are not deduplicated."""
    now = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=now,
        monitor_source="auth_log",
    )

    # Event 11 seconds later (outside 10-second window)
    event2 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=now + timedelta(seconds=11),
        monitor_source="wtmp",
    )

    # Both events should pass through
    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is not None


async def test_deduplicator_within_time_window(deduplicator):
    """Test that events within the time window are deduplicated."""
    now = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=now,
        monitor_source="auth_log",
    )

    # Event 5 seconds later (within 10-second window)
    event2 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=now + timedelta(seconds=5),
        monitor_source="wtmp",
    )

    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is None  # Should be filtered as duplicate


async def test_deduplicator_cleanup_old_events():
    """Test that old events are cleaned up from cache."""
    deduplicator = EventDeduplicator(window_seconds=1)  # Short window for testing

    event = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="auth_log",
    )

    # Process event
    await deduplicator.process_event(event)
    assert len(deduplicator.recent_events) == 1

    # Wait for cleanup window to pass
    await asyncio.sleep(1.5)

    # Process another event (should trigger cleanup)
    new_event = LoginEvent(
        username="bob",
        source_ip="192.168.1.200",
        login_type="ssh",
        timestamp=datetime.now(UTC),
        monitor_source="auth_log",
    )
    await deduplicator.process_event(new_event)

    # Old event should be cleaned up
    assert len(deduplicator.recent_events) == 1
    assert deduplicator.recent_events[0][0].username == "bob"


async def test_deduplicator_session_id_matching(deduplicator):
    """Test that events with matching session IDs are deduplicated."""
    timestamp = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
        session_id="session123",
    )

    event2 = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="wtmp",
        session_id="session123",
    )

    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is None  # Same session ID, should be duplicate


async def test_deduplicator_session_id_mismatch(deduplicator):
    """Test that events with different session IDs are not deduplicated."""
    timestamp = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
        session_id="session123",
    )

    event2 = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="wtmp",
        session_id="session456",
    )

    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is not None  # Different session IDs


async def test_deduplicator_tty_matching(deduplicator):
    """Test that events with matching TTY are deduplicated."""
    timestamp = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        login_type="console",
        timestamp=timestamp,
        monitor_source="auth_log",
        tty="tty1",
    )

    event2 = LoginEvent(
        username="alice",
        login_type="console",
        timestamp=timestamp,
        monitor_source="wtmp",
        tty="tty1",
    )

    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is None  # Same TTY, should be duplicate


async def test_deduplicator_partial_data_enrichment(deduplicator):
    """Test enrichment when events have partial data."""
    timestamp = datetime.now(UTC)

    # First event has IP but no session
    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
    )

    # Second event has session but no IP (different monitor might not capture IP)
    event2 = LoginEvent(
        username="alice",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="utmp",
        session_id="session123",
    )

    result1 = await deduplicator.process_event(event1)
    result2 = await deduplicator.process_event(event2)

    assert result1 is not None
    assert result2 is None

    # Check enrichment
    cached_event, _ = deduplicator.recent_events[0]
    assert cached_event.source_ip == "192.168.1.100"
    assert cached_event.session_id == "session123"
    assert cached_event.detected_by == ["auth_log", "utmp"]


async def test_deduplicator_concurrent_events(deduplicator):
    """Test that deduplicator handles concurrent events correctly."""
    timestamp = datetime.now(UTC)

    event1 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="auth_log",
    )

    event2 = LoginEvent(
        username="alice",
        source_ip="192.168.1.100",
        login_type="ssh",
        timestamp=timestamp,
        monitor_source="wtmp",
    )

    # Process events concurrently
    results = await asyncio.gather(
        deduplicator.process_event(event1), deduplicator.process_event(event2)
    )

    # One should be unique, one should be duplicate
    assert None in results
    assert any(r is not None for r in results)
