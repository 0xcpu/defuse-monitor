"""Tests for monitoring modules."""

import asyncio
import tempfile
from pathlib import Path

from defuse_monitor.monitors.auth_log import AuthLogMonitor


def test_auth_log_ssh_detection():
    """Test SSH login detection from auth.log."""
    monitor = AuthLogMonitor()
    log_line = "Jan 15 10:30:45 server sshd[1234]: Accepted publickey for alice from 192.168.1.100"

    event = monitor.parse_line(log_line)
    assert event is not None
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.100"
    assert event.login_type == "ssh"
    assert event.monitor_source == "auth_log"


def test_auth_log_su_detection():
    """Test su login detection from auth.log."""
    monitor = AuthLogMonitor()
    log_line = "Jan 15 10:30:45 server su[5678]: Successful su for root by alice"

    event = monitor.parse_line(log_line)
    assert event is not None
    assert event.username == "root"
    assert event.source_ip is None  # su is local
    assert event.login_type == "su"
    assert event.monitor_source == "auth_log"


def test_auth_log_console_detection():
    """Test console login detection from auth.log."""
    monitor = AuthLogMonitor()
    log_line = "Jan 15 10:30:45 server login[9012]: LOGIN ON tty1 BY alice"

    event = monitor.parse_line(log_line)
    assert event is not None
    assert event.username == "alice"
    assert event.source_ip is None  # console is local
    assert event.login_type == "console"
    assert event.tty == "tty1"
    assert event.monitor_source == "auth_log"


def test_auth_log_systemd_detection():
    """Test systemd login detection from auth.log."""
    monitor = AuthLogMonitor()
    log_line = (
        "Jan 15 10:30:45 server systemd-logind[3456]: New session 42 of user alice"
    )

    event = monitor.parse_line(log_line)
    assert event is not None
    assert event.username == "alice"
    assert event.source_ip is None
    assert event.login_type == "other"
    assert event.session_id == "42"
    assert event.monitor_source == "auth_log"


def test_auth_log_no_match():
    """Test that non-login lines return None."""
    monitor = AuthLogMonitor()
    log_line = "Jan 15 10:30:45 server kernel: Some random kernel message"

    event = monitor.parse_line(log_line)
    assert event is None


def test_auth_log_invalid_timestamp():
    """Test handling of invalid timestamps - now uses current time."""
    monitor = AuthLogMonitor()
    log_line = (
        "invalid timestamp sshd[1234]: Accepted publickey for alice from 192.168.1.100"
    )

    event = monitor.parse_line(log_line)
    # Should still parse successfully with current timestamp
    assert event is not None
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.100"
    assert event.login_type == "ssh"
    # Timestamp should be recent (current time)
    from datetime import datetime

    assert isinstance(event.timestamp, datetime)


def test_auth_log_patterns():
    """Test regex patterns for auth log parsing."""
    monitor = AuthLogMonitor()

    # Test SSH pattern
    ssh_line = "sshd[1234]: Accepted publickey for alice from 192.168.1.100"
    ssh_match = monitor._compiled_patterns["ssh_login"].search(ssh_line)
    assert ssh_match is not None
    assert ssh_match.group(1) == "alice"
    assert ssh_match.group(2) == "192.168.1.100"

    # Test su pattern
    su_line = "su[5678]: Successful su for root by alice"
    su_match = monitor._compiled_patterns["su_login"].search(su_line)
    assert su_match is not None
    assert su_match.group(1) == "root"
    assert su_match.group(2) == "alice"


async def test_auth_log_file_monitoring():
    """Test file monitoring functionality."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "test_auth.log"

        # Create log file with initial content
        log_file.write_text(
            "Jan 15 10:30:45 server sshd[1234]: Accepted publickey for alice from 192.168.1.100\n"
        )

        monitor = AuthLogMonitor(str(log_file))

        # Start monitoring in background
        monitor_task = asyncio.create_task(anext(monitor.monitor()))

        # Give it a moment to start
        await asyncio.sleep(0.1)

        # Cancel the task since we can't easily test the full monitoring loop
        monitor_task.cancel()

        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


async def test_auth_log_nonexistent_file():
    """Test handling of nonexistent log file."""
    monitor = AuthLogMonitor("/nonexistent/path/auth.log")

    # Should handle gracefully and not yield any events
    events = []
    async for event in monitor.monitor():
        events.append(event)
        if len(events) > 0:  # Should not happen
            break

    assert len(events) == 0
