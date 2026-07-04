"""Tests for defuse mechanism."""

import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

from defuse_monitor.core.events import LoginEvent
from defuse_monitor.defuse.handler import DefuseHandler


async def test_defuse_mechanism_success():
    """Test successful defuse with artifact creation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DefuseHandler(timeout_seconds=2, artifact_directory=temp_dir)

        login_event = LoginEvent(
            username="alice",
            source_ip="192.168.1.100",
            login_type="ssh",
            timestamp=datetime.now(),
            monitor_source="test",
        )

        # Start defuse in background
        defuse_task = asyncio.create_task(handler.initiate_defuse(login_event))

        # Wait a moment then create artifact
        await asyncio.sleep(0.5)

        # Generate the expected artifact filename using the same method as DefuseHandler
        expected_filename = handler.generate_artifact_filename(
            login_event.username, login_event.timestamp.isoformat()
        )
        artifact_path = Path(temp_dir) / f"{expected_filename}.key"
        artifact_path.touch()

        # Wait for defuse to complete
        result = await defuse_task
        assert result is True


async def test_defuse_mechanism_timeout():
    """Test defuse timeout when no artifact is created."""
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DefuseHandler(timeout_seconds=1, artifact_directory=temp_dir)

        login_event = LoginEvent(
            username="alice",
            source_ip="192.168.1.100",
            login_type="ssh",
            timestamp=datetime.now(),
            monitor_source="test",
        )

        # Start defuse but don't create artifact
        result = await handler.initiate_defuse(login_event)
        assert result is False


def test_secret_changes_artifact_filename():
    """Test that different secrets produce different artifact filenames."""
    username = "alice"
    timestamp_iso = datetime.now().isoformat()

    handler_none = DefuseHandler()
    handler_a = DefuseHandler(secret="secret-a")
    handler_b = DefuseHandler(secret="secret-b")

    name_none = handler_none.generate_artifact_filename(username, timestamp_iso)
    name_a = handler_a.generate_artifact_filename(username, timestamp_iso)
    name_b = handler_b.generate_artifact_filename(username, timestamp_iso)

    assert name_a != name_b
    assert name_none != name_a
    assert name_none != name_b


async def test_symlinked_artifact_not_accepted():
    """Test that a symlinked artifact is not treated as a valid defuse."""
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DefuseHandler(timeout_seconds=1, artifact_directory=temp_dir)

        login_event = LoginEvent(
            username="alice",
            source_ip="192.168.1.100",
            login_type="ssh",
            timestamp=datetime.now(),
            monitor_source="test",
        )

        session_id = handler.generate_artifact_filename(
            login_event.username, login_event.timestamp.isoformat()
        )
        artifact_path = Path(temp_dir) / f"{session_id}.key"

        target = Path(temp_dir) / "target"
        target.touch()
        artifact_path.symlink_to(target)

        result = await handler.initiate_defuse(login_event)
        assert result is False
