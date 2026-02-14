"""Event dispatcher for login events."""

import asyncio
import logging
from collections.abc import Awaitable, Callable

from .events import LoginEvent

logger = logging.getLogger(__name__)


class EventDispatcher:
    """Event dispatcher for login events."""

    def __init__(self) -> None:
        self._handlers: list[Callable[[LoginEvent], Awaitable[None]]] = []

    def register_handler(
        self, handler: Callable[[LoginEvent], Awaitable[None]]
    ) -> None:
        """Register an event handler."""
        self._handlers.append(handler)

    async def dispatch(self, event: LoginEvent) -> None:
        """Dispatch an event to all registered handlers."""
        logger.info("Dispatching login event: %s@%s", event.username, event.source_ip)

        tasks = [handler(event) for handler in self._handlers]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
