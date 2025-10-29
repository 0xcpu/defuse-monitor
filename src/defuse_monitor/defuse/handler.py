"""Defuse mechanism handler."""

import asyncio
import hashlib
import logging
from pathlib import Path

from ..core.events import LoginEvent

logger = logging.getLogger(__name__)


class DefuseHandler:
    """Handle defuse mechanism for login alerts."""

    def __init__(
        self, timeout_seconds: int = 60, artifact_directory: str = "/var/run/defuse"
    ):
        self.timeout_seconds = timeout_seconds
        self.artifact_directory = Path(artifact_directory)
        self._active_sessions: dict[str, asyncio.Task] = {}

    @staticmethod
    def generate_artifact_filename(username: str, timestamp_iso: str) -> str:
        """Generate predictable artifact filename from username and timestamp.

        Args:
            username: The username from the login event
            timestamp_iso: ISO format timestamp string (e.g., from LoginEvent.timestamp.isoformat())

        Returns:
            SHA256 hex digest that can be used as filename
        """
        hash_input = f"{username}:{timestamp_iso}".encode()
        return hashlib.sha256(hash_input).hexdigest()

    async def initiate_defuse(self, login_event: LoginEvent) -> bool:
        """Start defuse countdown for login event."""
        timestamp_str = login_event.timestamp.isoformat()
        session_id = self.generate_artifact_filename(
            login_event.username, timestamp_str
        )
        artifact_path = self.artifact_directory / f"{session_id}.key"

        logger.info(
            f"Initiating defuse for {login_event.username}, session: {session_id}"
        )
        logger.info(f"Waiting for artifact at: {artifact_path}")

        try:
            self.artifact_directory.mkdir(parents=True, exist_ok=True)
            defused = await self.wait_for_artifact(artifact_path, self.timeout_seconds)
            if defused:
                logger.info(f"Login defused for {login_event.username}")
                if artifact_path.exists():
                    artifact_path.unlink()
            else:
                logger.warning(f"Defuse timeout for {login_event.username}")

            return defused

        except Exception as e:
            logger.error(f"Error in defuse mechanism: {e}")
            return False

    async def wait_for_artifact(self, path: Path, timeout: int) -> bool:
        """Wait for artifact file creation."""
        # TODO: check if inotify-based monitoring would be more efficient?
        start_time = asyncio.get_event_loop().time()

        while True:
            if path.exists():
                logger.info(f"Artifact found: {path}")
                return True

            current_time = asyncio.get_event_loop().time()
            if current_time - start_time >= timeout:
                return False

            await asyncio.sleep(1)
