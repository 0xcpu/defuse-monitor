"""Alert dispatcher for login events."""

import logging

import aiohttp

from ..core.events import LoginEvent

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Send alerts for non-defused login events."""

    def __init__(
        self,
        discord_enabled: bool = False,
        webhook_url: str | None = None,
    ):
        self.discord_enabled = discord_enabled
        self.webhook_url = webhook_url

    async def send_alert(self, login_event: LoginEvent):
        """Dispatch alert through configured channels."""
        message = self._format_alert_message(login_event)

        logger.warning(f"ALERT: {message}")

        # Send through configured channels
        if self.discord_enabled and self.webhook_url:
            await self.send_discord_webhook(message)

        # TODO: Add other alert channels (email, webhook, etc.)

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
            # Discord webhook payload
            data = {
                "content": message,
                "username": "Defuse Monitor",
                "avatar_url": None,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=data) as response:
                    if response.status == 204:  # Discord webhook returns 204 on success
                        logger.info("Discord webhook alert sent successfully")
                    else:
                        logger.error(f"Discord webhook failed: {response.status}")
                        error_text = await response.text()
                        logger.error(f"Discord webhook error: {error_text}")

        except Exception as e:
            logger.error(f"Discord webhook alert failed: {e}")
            logger.warning(f"Discord Alert (NOT SENT): {message}")
