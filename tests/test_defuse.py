"""Tests for defuse mechanism."""

import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from defuse_monitor.core.events import LoginEvent
from defuse_monitor.defuse.handler import DefuseHandler


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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
