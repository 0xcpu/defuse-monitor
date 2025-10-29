"""Tests for accounting files monitor."""

import asyncio
import struct
import tempfile
from pathlib import Path

import pytest

from defuse_monitor.monitors.accounting import (
    DEAD_PROCESS,
    USER_PROCESS,
    AccountingFilesMonitor,
)


def create_utmp_record(
    ut_type: int = USER_PROCESS,
    pid: int = 12345,
    line: str = "pts/0",
    user: str = "testuser",
    host: str = "192.168.1.100",
    session: int = 1,
    tv_sec: int = 1700000000,
    tv_usec: int = 0,
) -> bytes:
    """Create a binary utmp record for testing."""
    # Pack according to UTMP_FORMAT: "hi32s4s32s256shhiii4i20x"
    record = struct.pack(
        "hi32s4s32s256shhiii4i20x",
        ut_type,
        pid,
        line.encode("utf-8"),
        b"",  # ut_id (4 bytes)
        user.encode("utf-8"),
        host.encode("utf-8"),
        0,  # exit_status
        0,  # exit_code
        session,
        tv_sec,
        tv_usec,
        0,  # addr_v6[0]
        0,  # addr_v6[1]
        0,  # addr_v6[2]
        0,  # addr_v6[3]
    )
    return record


def test_parse_utmp_record_ssh_login():
    """Test parsing a valid SSH login record."""
    monitor = AccountingFilesMonitor()
    record_data = create_utmp_record(
        ut_type=USER_PROCESS,
        pid=1234,
        line="pts/0",
        user="alice",
        host="192.168.1.100",
        session=42,
        tv_sec=1700000000,
    )

    record = monitor.parse_utmp_record(record_data)

    assert record is not None
    assert record["type"] == USER_PROCESS
    assert record["pid"] == 1234
    assert record["line"] == "pts/0"
    assert record["user"] == "alice"
    assert record["host"] == "192.168.1.100"
    assert record["session"] == 42
    assert record["tv_sec"] == 1700000000


def test_parse_utmp_record_console_login():
    """Test parsing a console login record."""
    monitor = AccountingFilesMonitor()
    record_data = create_utmp_record(
        ut_type=USER_PROCESS,
        pid=5678,
        line="tty1",
        user="bob",
        host="",  # Local console has no hostname
        session=10,
    )

    record = monitor.parse_utmp_record(record_data)

    assert record is not None
    assert record["user"] == "bob"
    assert record["line"] == "tty1"
    assert record["host"] == ""


def test_parse_utmp_record_empty():
    """Test parsing an empty record."""
    monitor = AccountingFilesMonitor()
    record_data = create_utmp_record(ut_type=DEAD_PROCESS, user="", host="", line="")

    record = monitor.parse_utmp_record(record_data)

    assert record is not None
    assert record["type"] == DEAD_PROCESS
    assert record["user"] == ""


def test_parse_utmp_record_short_data():
    """Test parsing with insufficient data."""
    monitor = AccountingFilesMonitor()
    short_data = b"short"

    record = monitor.parse_utmp_record(short_data)

    assert record is None


def test_parse_utmp_record_null_terminated_strings():
    """Test that null-terminated strings are handled correctly."""
    monitor = AccountingFilesMonitor()
    # Create record with null bytes in the middle of strings
    record_data = create_utmp_record(
        user="alice\x00garbage", host="192.168.1.100\x00more_garbage"
    )

    record = monitor.parse_utmp_record(record_data)

    assert record is not None
    assert record["user"] == "alice"  # Should stop at null byte
    assert record["host"] == "192.168.1.100"  # Should stop at null byte


def test_parse_utmp_record_unicode_handling():
    """Test handling of unicode/invalid characters."""
    monitor = AccountingFilesMonitor()
    # Create record with valid structure
    record_data = create_utmp_record(user="user123", host="host.local")

    record = monitor.parse_utmp_record(record_data)

    assert record is not None
    assert isinstance(record["user"], str)
    assert isinstance(record["host"], str)


def test_is_login_record_user_process():
    """Test identifying valid login records."""
    monitor = AccountingFilesMonitor()

    # Valid login
    record = {"type": USER_PROCESS, "user": "alice"}
    assert monitor._is_login_record(record)

    # Empty username
    record = {"type": USER_PROCESS, "user": ""}
    assert not monitor._is_login_record(record)

    # Whitespace-only username
    record = {"type": USER_PROCESS, "user": "   "}
    assert not monitor._is_login_record(record)

    # Wrong type
    record = {"type": DEAD_PROCESS, "user": "alice"}
    assert not monitor._is_login_record(record)


def test_record_to_login_event_ssh():
    """Test converting SSH login record to LoginEvent."""
    monitor = AccountingFilesMonitor()
    record = {
        "type": USER_PROCESS,
        "pid": 1234,
        "user": "alice",
        "host": "192.168.1.100",
        "line": "pts/0",
        "session": 42,
        "timestamp": monitor.parse_utmp_record(create_utmp_record(tv_sec=1700000000))[
            "timestamp"
        ],
    }

    event = monitor._record_to_login_event(record, "wtmp")

    assert event.username == "alice"
    assert event.source_ip == "192.168.1.100"
    assert event.login_type == "ssh"
    assert event.tty == "pts/0"
    assert event.session_id == "42"
    assert event.monitor_source == "wtmp"


def test_record_to_login_event_console():
    """Test converting console login record to LoginEvent."""
    monitor = AccountingFilesMonitor()
    record = {
        "type": USER_PROCESS,
        "pid": 5678,
        "user": "bob",
        "host": "",
        "line": "tty1",
        "session": 10,
        "timestamp": monitor.parse_utmp_record(create_utmp_record(tv_sec=1700000000))[
            "timestamp"
        ],
    }

    event = monitor._record_to_login_event(record, "utmp")

    assert event.username == "bob"
    assert event.source_ip is None
    assert event.login_type == "console"
    assert event.tty == "tty1"
    assert event.monitor_source == "utmp"


def test_record_to_login_event_other():
    """Test converting other login types to LoginEvent."""
    monitor = AccountingFilesMonitor()
    record = {
        "type": USER_PROCESS,
        "pid": 9999,
        "user": "service",
        "host": "",
        "line": "unknown",
        "session": 99,
        "timestamp": monitor.parse_utmp_record(create_utmp_record(tv_sec=1700000000))[
            "timestamp"
        ],
    }

    event = monitor._record_to_login_event(record, "wtmp")

    assert event.username == "service"
    assert event.login_type == "other"


@pytest.mark.asyncio
async def test_monitor_wtmp_nonexistent_file():
    """Test wtmp monitor with non-existent file."""
    monitor = AccountingFilesMonitor(wtmp_path="/nonexistent/wtmp", poll_interval=0.1)

    events = []
    async for event in monitor.monitor_wtmp():
        events.append(event)
        if len(events) > 0:  # Should never happen
            break

    assert len(events) == 0


@pytest.mark.asyncio
async def test_monitor_wtmp_new_records():
    """Test wtmp monitor detecting new login records."""
    with tempfile.TemporaryDirectory() as temp_dir:
        wtmp_file = Path(temp_dir) / "wtmp"

        # Create initial wtmp file with one record
        initial_record = create_utmp_record(
            pid=1000, user="alice", host="192.168.1.100", line="pts/0"
        )
        wtmp_file.write_bytes(initial_record)

        monitor = AccountingFilesMonitor(wtmp_path=str(wtmp_file), poll_interval=0.1)

        # Start monitoring (will start from end of file)
        monitor_task = asyncio.create_task(monitor.monitor_wtmp().__anext__())

        # Give it time to initialize
        await asyncio.sleep(0.05)

        # Append new record to wtmp
        new_record = create_utmp_record(
            pid=2000, user="bob", host="192.168.1.200", line="pts/1", tv_sec=1700000001
        )
        with open(wtmp_file, "ab") as f:
            f.write(new_record)

        # Wait for monitor to detect the new record
        try:
            event = await asyncio.wait_for(monitor_task, timeout=2.0)

            assert event.username == "bob"
            assert event.source_ip == "192.168.1.200"
            assert event.login_type == "ssh"
            assert event.monitor_source == "wtmp"

        except TimeoutError:
            pytest.fail("Monitor did not detect new wtmp record in time")


@pytest.mark.asyncio
async def test_monitor_wtmp_deduplication():
    """Test that wtmp monitor deduplicates records."""
    with tempfile.TemporaryDirectory() as temp_dir:
        wtmp_file = Path(temp_dir) / "wtmp"

        # Create initial empty wtmp file
        wtmp_file.write_bytes(b"")

        monitor = AccountingFilesMonitor(wtmp_path=str(wtmp_file), poll_interval=0.1)

        # Start monitoring
        events = []

        async def collect_events():
            async for event in monitor.monitor_wtmp():
                events.append(event)

        task = asyncio.create_task(collect_events())

        # Give monitor time to initialize
        await asyncio.sleep(0.15)

        # Append same record twice
        record = create_utmp_record(
            pid=1234, user="alice", host="192.168.1.100", tv_sec=1700000000
        )
        with open(wtmp_file, "ab") as f:
            f.write(record)
            f.write(record)  # Write duplicate

        # Give it time to process
        await asyncio.sleep(0.3)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should only detect one event, not duplicates
        assert len(events) == 1


@pytest.mark.asyncio
async def test_monitor_wtmp_file_rotation():
    """Test wtmp monitor handling file rotation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        wtmp_file = Path(temp_dir) / "wtmp"

        # Create initial file
        record1 = create_utmp_record(pid=1000, user="alice")
        wtmp_file.write_bytes(record1)

        monitor = AccountingFilesMonitor(wtmp_path=str(wtmp_file), poll_interval=0.1)

        # Start monitoring
        events = []

        async def collect_events():
            async for event in monitor.monitor_wtmp():
                events.append(event)

        task = asyncio.create_task(collect_events())
        await asyncio.sleep(0.5)

        # Simulate rotation: delete old file and create new one
        wtmp_file.unlink()
        await asyncio.sleep(0.5)  # Small delay for filesystem
        record2 = create_utmp_record(pid=2000, user="bob", tv_sec=1700000001)
        wtmp_file.write_bytes(record2)

        # Give monitor time to detect rotation and new record
        await asyncio.sleep(1.0)

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should detect the record after rotation
        assert len(events) >= 1
        assert any(e.username == "bob" for e in events)


@pytest.mark.asyncio
async def test_monitor_utmp_nonexistent_file():
    """Test utmp monitor with non-existent file."""
    monitor = AccountingFilesMonitor(utmp_path="/nonexistent/utmp", poll_interval=0.1)

    events = []
    async for event in monitor.monitor_utmp():
        events.append(event)
        if len(events) > 0:  # Should never happen
            break

    assert len(events) == 0


@pytest.mark.asyncio
async def test_monitor_utmp_new_user():
    """Test utmp monitor detecting new logged-in user."""
    with tempfile.TemporaryDirectory() as temp_dir:
        utmp_file = Path(temp_dir) / "utmp"

        # Create initial utmp with one user
        record1 = create_utmp_record(pid=1000, user="alice")
        utmp_file.write_bytes(record1)

        monitor = AccountingFilesMonitor(utmp_path=str(utmp_file), poll_interval=0.1)

        # Start monitoring and collect events
        events = []

        async def collect_events():
            async for event in monitor.monitor_utmp():
                events.append(event)

        task = asyncio.create_task(collect_events())

        # Give it time to read initial state (alice will be detected as "new")
        await asyncio.sleep(0.15)

        # Add new user to utmp
        record2 = create_utmp_record(pid=2000, user="bob", tv_sec=1700000001)
        utmp_file.write_bytes(record1 + record2)  # Both users logged in

        # Give monitor time to detect bob
        await asyncio.sleep(0.3)

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have detected both alice (on startup) and bob (new login)
        assert len(events) >= 2
        usernames = [e.username for e in events]
        assert "alice" in usernames
        assert "bob" in usernames
        assert all(e.monitor_source == "utmp" for e in events)


@pytest.mark.asyncio
async def test_monitor_wtmp_non_login_records_ignored():
    """Test that non-login records are ignored."""
    with tempfile.TemporaryDirectory() as temp_dir:
        wtmp_file = Path(temp_dir) / "wtmp"

        # Create wtmp with non-login records
        dead_record = create_utmp_record(ut_type=DEAD_PROCESS, user="")
        login_record = create_utmp_record(ut_type=USER_PROCESS, pid=1234, user="alice")

        wtmp_file.write_bytes(dead_record)

        monitor = AccountingFilesMonitor(wtmp_path=str(wtmp_file), poll_interval=0.1)

        # Start monitoring
        monitor_task = asyncio.create_task(monitor.monitor_wtmp().__anext__())
        await asyncio.sleep(0.1)

        # Append login record
        with open(wtmp_file, "ab") as f:
            f.write(login_record)

        try:
            event = await asyncio.wait_for(monitor_task, timeout=2.0)

            # Should only get the login record, not the dead process
            assert event.username == "alice"

        except TimeoutError:
            pytest.fail("Monitor did not detect login record")


@pytest.mark.asyncio
async def test_monitor_wtmp_file_truncation():
    """Test wtmp monitor handling file truncation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        wtmp_file = Path(temp_dir) / "wtmp"

        # Create initial file with records
        record1 = create_utmp_record(pid=1000, user="alice")
        record2 = create_utmp_record(pid=2000, user="bob", tv_sec=1700000001)
        wtmp_file.write_bytes(record1 + record2)

        monitor = AccountingFilesMonitor(wtmp_path=str(wtmp_file), poll_interval=0.1)

        events = []

        async def collect_events():
            async for event in monitor.monitor_wtmp():
                events.append(event)

        task = asyncio.create_task(collect_events())
        await asyncio.sleep(0.2)

        # Truncate file (simulate log rotation/clear)
        wtmp_file.write_bytes(b"")

        await asyncio.sleep(0.2)

        # Add new record after truncation
        record3 = create_utmp_record(pid=3000, user="charlie", tv_sec=1700000002)
        wtmp_file.write_bytes(record3)

        await asyncio.sleep(0.3)

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should detect record after truncation
        assert any(e.username == "charlie" for e in events)
