"""Authentication log monitor."""

import asyncio
import io
import logging
import re
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from watchdog.events import (
    DirModifiedEvent,
    DirMovedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from ..core.events import LoginEvent

logger = logging.getLogger(__name__)


class _LogFileHandler(FileSystemEventHandler):
    """File system event handler for auth log monitoring."""

    def __init__(self, monitor_instance):
        self.monitor = monitor_instance
        self.queue: asyncio.Queue[LoginEvent] = None  # set by monitor
        self._event_loop: asyncio.AbstractEventLoop = None  # set by monitor
        self._file_handle: io.TextIOWrapper = None
        self._current_inode = None
        self._position: int = 0
        self._partial_line: str = ""
        self._background_tasks = set()

    def set_queue_and_loop(
        self, queue: asyncio.Queue[LoginEvent], event_loop: asyncio.AbstractEventLoop
    ):
        """Set the async queue and event loop for cross-thread communication."""
        self.queue = queue
        self._event_loop = event_loop

    def on_modified(self, event: DirModifiedEvent | FileModifiedEvent):
        if event.is_directory:
            return
        if Path(str(event.src_path)) == self.monitor.log_path:
            self._schedule_task(self._process_file_changes())

    def on_moved(self, event: DirMovedEvent | FileMovedEvent):
        if Path(str(event.dest_path)) == self.monitor.log_path:
            self._schedule_task(self._handle_rotation())

    def _schedule_task(self, coro):
        """Schedule a background task from watchdog thread to main event loop."""
        if self._event_loop is None:
            logger.error("Event loop not set for cross-thread task scheduling")
            return

        try:
            # chedule the coroutine to run in the main event loop from this thread
            future = asyncio.run_coroutine_threadsafe(coro, self._event_loop)
            self._background_tasks.add(future)
            future.add_done_callback(self._background_tasks.discard)
        except Exception as e:
            logger.error(f"Failed to schedule task from watchdog thread: {e}")

    async def _handle_rotation(self):
        """Handle log file rotation."""
        self._close_file()
        self._reset_state()
        await self._process_file_changes()

    def _close_file(self):
        """Close the current file handle."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    def _reset_state(self):
        """Reset file monitoring state."""
        self._current_inode = None
        self._position = 0
        self._partial_line = ""

    async def _process_file_changes(self):
        """Process new content in the log file."""
        try:
            if not self._check_file_rotation():
                return

            self._ensure_file_open()
            await self._read_and_process_new_content()

        except OSError as e:
            logger.error(f"Error reading log file: {e}")
            self._close_file()

    def _check_file_rotation(self) -> bool:
        """Check if file was rotated and handle if needed."""
        try:
            current_stat = self.monitor.log_path.stat()
            if self._current_inode and current_stat.st_ino != self._current_inode:
                # fiile was rotated, handle it
                self._schedule_task(self._handle_rotation())
                return False
            return True
        except OSError:
            return False

    def _ensure_file_open(self):
        """Ensure the log file is open for reading."""
        if not self._file_handle:
            self._file_handle = open(
                self.monitor.log_path, encoding="utf-8", errors="replace"
            )
            current_stat = self.monitor.log_path.stat()
            self._current_inode = current_stat.st_ino
            # start from the end of the file
            self._file_handle.seek(0, 2)
            self._position = self._file_handle.tell()

    async def _read_and_process_new_content(self):
        """Read new content and process complete lines."""
        self._file_handle.seek(self._position)
        new_content = self._file_handle.read()

        if new_content:
            lines = (self._partial_line + new_content).split("\n")
            self._partial_line = lines[-1]  # Last line might be incomplete

            for line in lines[:-1]:
                if line.strip():
                    event = self.monitor.parse_line(line)
                    if event and self.queue:
                        await self.queue.put(event)

            self._position = self._file_handle.tell()

    def cleanup(self):
        """Clean up resources."""
        self._close_file()
        for task in list(self._background_tasks):
            if hasattr(task, "cancel"):
                task.cancel()


class AuthLogMonitor:
    """Monitor authentication log files for login events."""

    PATTERNS: ClassVar = {
        "ssh_login": r"sshd\[\d+\]: Accepted \w+ for (\S+) from (\S+)",
        "su_login": r"su\[\d+\]: Successful su for (\S+) by (\S+)",
        "console_login": r"login\[\d+\]: LOGIN ON (\S+) BY (\S+)",
        "systemd_login": r"systemd-logind\[\d+\]: New session (\d+) of user (\S+)",
    }

    def __init__(self, log_path: str = "/var/log/auth.log"):
        self.log_path: Path = Path(log_path)
        self._compiled_patterns: dict[str, re.Pattern] = {
            name: re.compile(pattern) for name, pattern in self.PATTERNS.items()
        }

    def parse_line(self, line: str) -> LoginEvent | None:
        """Parse a log line and return a LoginEvent if a login is detected."""
        # use current timestamp so we don't have to parse it from the log line
        # and deal with potential timestamp format variations
        timestamp = datetime.now()

        for pattern_name, pattern in self._compiled_patterns.items():
            match = pattern.search(line)
            if not match:
                continue

            if pattern_name == "ssh_login":
                return LoginEvent(
                    username=match.group(1),
                    source_ip=match.group(2),
                    login_type="ssh",
                    timestamp=timestamp,
                    monitor_source="auth_log",
                )
            elif pattern_name == "su_login":
                return LoginEvent(
                    username=match.group(1),
                    source_ip=None,  # su is local
                    login_type="su",
                    timestamp=timestamp,
                    monitor_source="auth_log",
                )
            elif pattern_name == "console_login":
                tty = match.group(1)
                username = match.group(2)
                return LoginEvent(
                    username=username,
                    source_ip=None,  # console is local
                    login_type="console",
                    timestamp=timestamp,
                    tty=tty,
                    monitor_source="auth_log",
                )
            elif pattern_name == "systemd_login":
                session_id = match.group(1)
                username = match.group(2)
                return LoginEvent(
                    username=username,
                    source_ip=None,
                    login_type="other",
                    timestamp=timestamp,
                    session_id=session_id,
                    monitor_source="auth_log",
                )

        return None

    async def monitor(self) -> AsyncIterator[LoginEvent]:
        """Monitor the authentication log for new login events."""

        logger.info(f"Starting auth log monitor on {self.log_path}")

        if not self.log_path.exists():
            logger.warning(f"Auth log file does not exist: {self.log_path}")
            return

        try:
            with open(self.log_path) as f:
                f.read(1)
            logger.info("Auth log file is readable")
        except PermissionError:
            logger.error(
                f"Permission denied reading {self.log_path}. Try running with sudo or add user to 'adm' group"
            )
            return
        except Exception as e:
            logger.error(f"Cannot read auth log file: {e}")
            return

        try:
            logger.info("Starting watchdog-based monitoring")
            async for event in self._monitor_with_watchdog():
                yield event
        except Exception as e:
            logger.warning(f"Watchdog monitoring failed: {e}, falling back to polling")
            logger.info("Starting polling-based monitoring")
            async for event in self._monitor_with_polling():
                yield event

    async def _monitor_with_watchdog(self) -> AsyncIterator[LoginEvent]:
        """Monitor using watchdog (inotify on Linux)."""
        handler = _LogFileHandler(self)
        queue: asyncio.Queue[LoginEvent] = asyncio.Queue()
        # pass the event loop to the handler for cross-thread communication
        current_loop = asyncio.get_running_loop()
        handler.set_queue_and_loop(queue, current_loop)

        observer = Observer()
        observer.schedule(handler, str(self.log_path.parent), recursive=False)
        observer.start()

        try:
            await handler._process_file_changes()

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield event
                except TimeoutError:
                    continue
        finally:
            observer.stop()
            observer.join()
            handler.cleanup()

    def _initialize_polling_state(self):
        """Initialize state for polling-based monitoring."""
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                position = f.tell()
                inode = self.log_path.stat().st_ino
                return position, inode, ""
        except OSError as e:
            logger.error(f"Cannot access log file: {e}")
            return None

    def _check_rotation(self, last_inode):
        """Check if log file was rotated."""
        try:
            current_stat = self.log_path.stat()
            if last_inode and current_stat.st_ino != last_inode:
                logger.info("Log rotation detected")
                return True, current_stat.st_ino
            return False, current_stat.st_ino
        except OSError:
            return False, last_inode

    def _read_new_content(self, last_position, partial_line):
        """Read and process new content from log file."""
        try:
            current_stat = self.log_path.stat()
            if current_stat.st_size <= last_position:
                return [], last_position, partial_line

            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                f.seek(last_position)
                new_content = f.read()

                if new_content:
                    lines = (partial_line + new_content).split("\n")
                    partial_line = lines[-1]  # Last line might be incomplete

                    events = []
                    for line in lines[:-1]:
                        if line.strip():
                            event = self.parse_line(line)
                            if event:
                                events.append(event)

                    return events, f.tell(), partial_line

            return [], last_position, partial_line
        except OSError:
            return [], last_position, partial_line

    async def _monitor_with_polling(self) -> AsyncIterator[LoginEvent]:
        """Fallback polling-based monitoring."""

        state = self._initialize_polling_state()
        if state is None:
            logger.error("Failed to initialize polling state")
            return

        last_position, last_inode, partial_line = state

        while True:
            try:
                rotated, last_inode = self._check_rotation(last_inode)
                if rotated:
                    last_position = 0
                    partial_line = ""

                events, last_position, partial_line = self._read_new_content(
                    last_position, partial_line
                )

                for event in events:
                    yield event

                await asyncio.sleep(1.0)

            except OSError as e:
                logger.error(f"Error polling log file: {e}")
                await asyncio.sleep(5.0)
            except Exception as e:
                logger.error(f"Unexpected error in polling: {e}")
                await asyncio.sleep(1.0)
