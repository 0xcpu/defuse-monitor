"""Alert dispatcher for login events."""

import logging

import aiohttp
from pydantic import HttpUrl

from ..core.events import LoginEvent

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Send alerts for non-defused login events."""

    def __init__(
        self,
        discord_enabled: bool = False,
        webhook_url: HttpUrl | None = None,
    ):
        self.discord_enabled = discord_enabled
        self.webhook_url = str(webhook_url) if webhook_url else None
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create a reusable aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def send_alert(self, login_event: LoginEvent):
        """Dispatch alert through configured channels."""
        message = self._format_alert_message(login_event)

        logger.warning("ALERT: %s", message)

        if self.discord_enabled and self.webhook_url:
            await self.send_discord_webhook(message)

    def _format_alert_message(self, login_event: LoginEvent) -> str:
        """Format login event into alert message."""
        return (
            f"LOGIN DETECTED: User '{login_event.username}' "
            f"logged in via {login_event.login_type} "
            f"from {login_event.source_ip or 'local'} "
            f"at {login_event.timestamp.isoformat()}"
        )

    async def send_discord_webhook(self, message: str):
        """Send Discord webhook alert."""
        if not self.webhook_url:
            logger.error("Discord webhook URL not configured")
            return

        try:
            data = {
                "content": message,
                "username": "Defuse Monitor",
                "avatar_url": None,
            }

            session = await self._get_session()
            async with session.post(self.webhook_url, json=data) as response:
                if response.status == 204:  # Discord webhook returns 204 on success
                    logger.info("Discord webhook alert sent successfully")
                else:
                    logger.error("Discord webhook failed: %s", response.status)
                    error_text = await response.text()
                    logger.error("Discord webhook error: %s", error_text)

        except Exception as e:
            logger.error("Discord webhook alert failed: %s", e)
            logger.warning("Discord Alert (NOT SENT): %s", message)
