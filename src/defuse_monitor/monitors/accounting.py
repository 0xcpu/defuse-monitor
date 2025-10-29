"""System accounting files monitor."""

import asyncio
import logging
import struct
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from ..core.events import LoginEvent

logger = logging.getLogger(__name__)

# Constants from utmp.h
EMPTY = 0  # No valid user accounting information
RUN_LVL = 1  # Run level change
BOOT_TIME = 2  # System boot time
NEW_TIME = 3  # Time after system clock change
OLD_TIME = 4  # Time before system clock change
INIT_PROCESS = 5  # Process spawned by init
LOGIN_PROCESS = 6  # Session leader for user login
USER_PROCESS = 7  # Normal process
DEAD_PROCESS = 8  # Terminated process


class AccountingFilesMonitor:
    """Monitor binary accounting files for login events."""

    # utmp structure format (Linux x86_64)
    # Based on /usr/include/bits/utmp.h
    UTMP_FORMAT = "hi32s4s32s256shhiii4i20x"  # Total: 384 bytes
    UTMP_SIZE = struct.calcsize(UTMP_FORMAT)

    def __init__(
        self,
        wtmp_path: str = "/var/log/wtmp",
        utmp_path: str = "/var/run/utmp",
        poll_interval: float = 1.0,
    ):
        self.wtmp_path = Path(wtmp_path)
        self.utmp_path = Path(utmp_path)
        self.poll_interval = poll_interval
        # TODO: implement an enum or dataclass
        self._seen_records: set[tuple[int, str, int]] = set()  # (pid, user, timestamp)
        self._wtmp_was_missing = False

    def _check_file_exists(self, file_path: Path, file_type: str) -> bool:
        """Check if file exists and log appropriate message."""
        if not file_path.exists():
            logger.warning(f"{file_type} file does not exist: {file_path}")
            return False
        return True

    def _read_records_from_file(self, file_path: Path) -> list[dict[str, Any]]:
        """Read all records from a utmp/wtmp file.

        Returns:
            List of parsed login records (only USER_PROCESS types)
        """
        records = []
        try:
            with open(file_path, "rb") as f:
                while True:
                    record_data = f.read(self.UTMP_SIZE)
                    if len(record_data) < self.UTMP_SIZE:
                        break

                    record = self.parse_utmp_record(record_data)
                    if record and self._is_login_record(record):
                        records.append(record)
        except OSError as e:
            logger.error(f"Error reading {file_path}: {e}")
        return records

    def _process_new_wtmp_records(self, new_data: bytes) -> list[LoginEvent]:
        """Process new binary records from wtmp file.

        Args:
            new_data: Binary data to process

        Returns:
            List of LoginEvent for each new login found
        """
        events = []
        offset = 0
        while offset + self.UTMP_SIZE <= len(new_data):
            record_data = new_data[offset : offset + self.UTMP_SIZE]
            record = self.parse_utmp_record(record_data)

            if record and self._is_login_record(record):
                record_key = (record["pid"], record["user"], record["tv_sec"])
                if record_key not in self._seen_records:
                    self._seen_records.add(record_key)
                    events.append(self._record_to_login_event(record, "wtmp"))

            offset += self.UTMP_SIZE

        return events

    def _handle_wtmp_rotation(
        self, current_inode: int, last_inode: int
    ) -> tuple[int | None, int]:
        """Handle wtmp file rotation.

        Returns:
            Tuple of (new_position or None, new_inode)
        """
        # detect rotation via inode change OR file reappearance after being missing
        if current_inode != last_inode or self._wtmp_was_missing:
            if self._wtmp_was_missing:
                logger.info(
                    "wtmp file reappeared after being missing, treating as rotation"
                )
                self._wtmp_was_missing = False
            else:
                logger.info("wtmp file rotation detected (inode change)")
            self._seen_records.clear()
            return 0, current_inode
        return None, last_inode

    def _handle_wtmp_truncation(
        self, current_size: int, last_position: int
    ) -> int | None:
        """Handle wtmp file truncation.

        Returns:
            New position (0) if truncated, None otherwise
        """
        if current_size < last_position:
            logger.info("wtmp file truncated, resetting position")
            self._seen_records.clear()
            return 0
        return None

    async def _handle_wtmp_error(self, error: Exception) -> None:
        """Handle errors during wtmp monitoring with appropriate retry delays."""
        if isinstance(error, FileNotFoundError):
            self._wtmp_was_missing = True
            logger.debug("wtmp file not found, waiting for rotation...")
            await asyncio.sleep(self.poll_interval)
        elif isinstance(error, OSError):
            logger.error(f"Error reading wtmp: {error}")
            await asyncio.sleep(5.0)
        else:
            logger.error(f"Unexpected error in wtmp monitor: {error}", exc_info=True)
            await asyncio.sleep(1.0)

    def parse_utmp_record(self, data: bytes) -> dict[str, Any] | None:
        """Parse a single utmp/wtmp record.

        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        if len(data) < self.UTMP_SIZE:
            logger.debug("Invalid wtmp record size")
            return None

        try:
            (
                ut_type,
                ut_pid,
                ut_line,
                _ut_id,
                ut_user,
                ut_host,
                _exit_status,
                _exit_code,
                ut_session,
                ut_tv_sec,
                ut_tv_usec,
                _addr_v6_0,
                _addr_v6_1,
                _addr_v6_2,
                _addr_v6_3,
            ) = struct.unpack(self.UTMP_FORMAT, data[: self.UTMP_SIZE])

            # C strings (null-terminated) -> Python strings
            username = ut_user.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            hostname = ut_host.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            line = ut_line.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

            return {
                "type": ut_type,
                "pid": ut_pid,
                "line": line,
                "user": username,
                "host": hostname,
                "session": ut_session,
                "timestamp": datetime.fromtimestamp(ut_tv_sec),
                "tv_sec": ut_tv_sec,
                "tv_usec": ut_tv_usec,
            }

        except (struct.error, UnicodeDecodeError, ValueError, OSError) as e:
            logger.debug(f"Failed to parse utmp record: {e}")
            return None

    def _is_login_record(self, record: dict[str, Any]) -> bool:
        """Check if record represents a user login."""
        return (
            record["type"] == USER_PROCESS
            and bool(record["user"])
            and bool(record["user"].strip())
        )

    def _record_to_login_event(self, record: dict[str, Any], source: str) -> LoginEvent:
        """Convert utmp record to LoginEvent."""
        line = record["line"]
        host = record["host"]

        login_type: Literal["ssh", "console", "su", "other"]
        if line.startswith("pts/") or (line.startswith("tty") and host):
            login_type = "ssh"
        elif line.startswith("tty"):
            login_type = "console"
        else:
            login_type = "other"

        return LoginEvent(
            username=record["user"],
            source_ip=host if host else None,
            login_type=login_type,
            timestamp=record["timestamp"],
            tty=line if line else None,
            session_id=str(record["session"]) if record["session"] else None,
            monitor_source=source,
        )

    async def monitor_wtmp(self) -> AsyncIterator[LoginEvent]:
        """Monitor wtmp for new login records."""
        logger.info(f"Starting wtmp monitor on {self.wtmp_path}")

        if not self._check_file_exists(self.wtmp_path, "wtmp"):
            return

        # capture only new logins, thus start from end of file
        try:
            last_position = self.wtmp_path.stat().st_size
            last_inode = self.wtmp_path.stat().st_ino
        except OSError as e:
            logger.error(f"Cannot access wtmp file: {e}")
            return

        while True:
            try:
                current_stat = self.wtmp_path.stat()
                rotation_result = self._handle_wtmp_rotation(
                    current_stat.st_ino, last_inode
                )
                new_pos, last_inode = rotation_result
                if new_pos is not None:
                    last_position = new_pos

                if current_stat.st_size > last_position:
                    with open(self.wtmp_path, "rb") as f:
                        f.seek(last_position)
                        new_data = f.read()

                        for event in self._process_new_wtmp_records(new_data):
                            yield event

                        last_position = f.tell()
                else:
                    truncation_pos = self._handle_wtmp_truncation(
                        current_stat.st_size, last_position
                    )
                    if truncation_pos is not None:
                        last_position = truncation_pos

                await asyncio.sleep(self.poll_interval)

            except Exception as e:
                await self._handle_wtmp_error(e)

    async def monitor_utmp(self) -> AsyncIterator[LoginEvent]:
        """Monitor utmp for changes in logged-in users."""
        logger.info(f"Starting utmp monitor on {self.utmp_path}")

        if not self._check_file_exists(self.utmp_path, "utmp"):
            return

        current_users: dict[tuple[int, str], dict[str, Any]] = {}

        while True:
            try:
                records = self._read_records_from_file(self.utmp_path)
                new_users = {
                    (record["pid"], record["user"]): record for record in records
                }

                for user_key, record in new_users.items():
                    if user_key not in current_users:
                        yield self._record_to_login_event(record, "utmp")

                current_users = new_users

                await asyncio.sleep(self.poll_interval)

            except OSError as e:
                logger.error(f"Error reading utmp: {e}")
                await asyncio.sleep(5.0)
            except Exception as e:
                logger.error(f"Unexpected error in utmp monitor: {e}", exc_info=True)
                await asyncio.sleep(1.0)
