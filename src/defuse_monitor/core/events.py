"""Event definitions for login monitoring."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class LoginEvent(BaseModel):
    """Represents a detected login event."""

    username: str
    source_ip: str | None = None
    login_type: Literal["ssh", "console", "su", "other"]
    timestamp: datetime
    session_id: str | None = None
    tty: str | None = None
    monitor_source: str  # Which monitor detected this event
    detected_by: list[
        str
    ] = []  # List of monitors that detected this event (for deduplication)
