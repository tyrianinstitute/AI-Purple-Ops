"""Rate limiter for API calls."""

from __future__ import annotations

import time
from threading import Lock


class RateLimiter:
    """Token bucket rate limiter for API calls.

    Args:
        rpm: Requests per minute limit
    """

    def __init__(self, rpm: int = 60) -> None:
        """Initialize rate limiter.

        Args:
            rpm: Requests per minute limit
        """
        self.rpm = rpm
        self.interval = 60.0 / rpm if rpm > 0 else 0.0  # seconds between requests
        self.last_request = 0.0
        self.lock = Lock()

    def acquire(self) -> None:
        """Wait until next request is allowed."""
        if self.rpm <= 0:
            return  # No rate limiting

        with self.lock:
            now = time.time()
            time_since_last = now - self.last_request

            if time_since_last < self.interval:
                sleep_time = self.interval - time_since_last
                time.sleep(sleep_time)

            self.last_request = time.time()
