"""Rate limiting utilities for network operations."""

import time
from typing import Optional


class RateLimiter:
    """Simple rate limiter to control request frequency."""

    def __init__(self, requests_per_second: float = 10.0):
        """Initialize rate limiter.

        Args:
            requests_per_second: Maximum requests per second
        """
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request_time: Optional[float] = None

    def wait(self) -> None:
        """Wait if necessary to maintain rate limit."""
        if self.min_interval <= 0:
            return

        current_time = time.time()

        if self.last_request_time is not None:
            elapsed = current_time - self.last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
                current_time = time.time()

        self.last_request_time = current_time
