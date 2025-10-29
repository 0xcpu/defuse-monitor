"""Event deduplication for login monitoring."""

import asyncio
import logging
from collections import deque
from datetime import UTC, datetime

from .events import LoginEvent

logger = logging.getLogger(__name__)


class EventDeduplicator:
    """
    Deduplicate login events from multiple monitors.

    Maintains sliding window cache of recent events and correlates
    similar events to prevent duplicate alerts.
    """

    def __init__(self, window_seconds: int = 10):
        """
        Initialize the event deduplicator.

        Args:
            window_seconds: Time window for considering events as duplicates
        """
        self.window_seconds = window_seconds
        self.recent_events: deque[tuple[LoginEvent, float]] = deque()
        self._lock = asyncio.Lock()

    async def process_event(self, event: LoginEvent) -> LoginEvent | None:
        """
        Process incoming event, returns None if duplicate.

        Args:
            event: The login event to process

        Returns:
            Enriched LoginEvent if unique, None if duplicate
        """
        async with self._lock:
            self._cleanup_old_events()

            current_time = datetime.now(UTC).timestamp()

            for existing_event, event_time in self.recent_events:
                if self._is_duplicate(existing_event, event):
                    # Found a duplicate - enrich the existing event
                    logger.debug(
                        f"Duplicate event detected: {event.username} from "
                        f"{event.monitor_source} (original: {existing_event.monitor_source})"
                    )
                    enriched_event = self._enrich_event(existing_event, event)

                    self.recent_events.remove((existing_event, event_time))
                    self.recent_events.append((enriched_event, event_time))

                    return None

            # This is a unique event - add to cache
            # Initialize detected_by with the monitor_source
            event.detected_by = [event.monitor_source]
            self.recent_events.append((event, current_time))

            logger.debug(
                f"New unique event: {event.username} from {event.monitor_source}"
            )
            return event

    def _is_duplicate(self, event1: LoginEvent, event2: LoginEvent) -> bool:
        """
        Determine if two events represent the same physical login.

        Correlation criteria:
        - Same username (required)
        - Timestamp within window_seconds (required)
        - Same source_ip (if both available and match)
        - Same session_id (if both available and match)
        - Same tty (if both available and match)

        Args:
            event1: First event
            event2: Second event

        Returns:
            True if events are duplicates, False otherwise
        """
        if event1.username != event2.username:
            return False

        # Event time proximity. Ensure events are within the specified window.
        time_diff = abs((event1.timestamp - event2.timestamp).total_seconds())
        if time_diff > self.window_seconds:
            return False

        if (
            event1.source_ip
            and event2.source_ip
            and event1.source_ip != event2.source_ip
        ):
            return False

        if (
            event1.session_id
            and event2.session_id
            and event1.session_id != event2.session_id
        ):
            return False

        if event1.tty and event2.tty and event1.tty != event2.tty:
            return False

        return True

    def _enrich_event(self, existing: LoginEvent, new: LoginEvent) -> LoginEvent:
        """
        Merge information from duplicate event into existing one.

        Updates the detected_by list to track which monitors saw this login.

        Args:
            existing: Existing event in cache
            new: New duplicate event

        Returns:
            Enriched LoginEvent with updated detected_by list
        """
        if new.monitor_source not in existing.detected_by:
            existing.detected_by.append(new.monitor_source)

        if not existing.source_ip and new.source_ip:
            existing.source_ip = new.source_ip

        if not existing.session_id and new.session_id:
            existing.session_id = new.session_id

        if not existing.tty and new.tty:
            existing.tty = new.tty

        logger.debug(
            f"Enriched event for {existing.username}, now detected by: {existing.detected_by}"
        )

        return existing

    def _cleanup_old_events(self):
        """Remove events older than window from cache."""
        current_time = datetime.now(UTC).timestamp()
        cutoff_time = current_time - self.window_seconds

        while self.recent_events and self.recent_events[0][1] < cutoff_time:
            old_event, _ = self.recent_events.popleft()
            logger.debug(
                f"Cleaned up old event: {old_event.username} from {old_event.monitor_source}"
            )
