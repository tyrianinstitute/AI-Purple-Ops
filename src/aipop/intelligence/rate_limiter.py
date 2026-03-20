"""Token bucket rate limiter with jitter support.

Implements token bucket algorithm for rate limiting API requests
with optional jitter to avoid predictable patterns.
"""

from __future__ import annotations

import logging
import random
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter.

    Allows bursts while maintaining average rate limit.
    Uses monotonic time to prevent clock skew issues.

    Example:
        >>> limiter = RateLimiter(rate_per_minute=60, burst=5)
        >>> limiter.acquire()  # Blocks if rate limit exceeded

    Attributes:
        capacity: Maximum burst size (tokens)
        tokens: Current available tokens
        rate_per_sec: Tokens generated per second
        last: Last time tokens were refilled
        jitter_s: Optional random delay in seconds
    """

    def __init__(
        self,
        rate_per_minute: float,
        burst: int = 1,
        jitter_s: float = 0.0,
    ) -> None:
        """Initialize rate limiter.

        Args:
            rate_per_minute: Maximum requests per minute
            burst: Maximum burst size (default 1)
            jitter_s: Optional jitter in seconds (default 0)
        """
        self.capacity = max(1, int(burst))
        self.tokens = float(self.capacity)
        self.rate_per_sec = rate_per_minute / 60.0
        self.last = time.monotonic()
        self.jitter_s = float(jitter_s)

        logger.debug(
            f"RateLimiter initialized: {rate_per_minute}/min, " f"burst={burst}, jitter={jitter_s}s"
        )

    def acquire(self) -> float:
        """Acquire a token, blocking if necessary.

        Returns:
            Time waited in seconds (0 if no wait)
        """
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now

        # Refill tokens based on elapsed time
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)

        wait_time = 0.0

        if self.tokens < 1.0:
            # Not enough tokens, need to wait
            deficit = 1.0 - self.tokens
            wait = deficit / self.rate_per_sec

            # Add optional jitter
            if self.jitter_s > 0:
                jitter = random.uniform(0, self.jitter_s)
                wait += jitter
                logger.debug(f"Adding jitter: {jitter:.3f}s")

            wait_time = max(0.0, wait)

            if wait_time > 0:
                logger.info(f"Rate limiting: waiting {wait_time:.2f}s")
                time.sleep(wait_time)

            self.tokens = 0.0
        else:
            # Consume one token
            self.tokens -= 1.0

        return wait_time

    def try_acquire(self) -> bool:
        """Try to acquire a token without blocking.

        Returns:
            True if token acquired, False if rate limit would be exceeded
        """
        now = time.monotonic()
        elapsed = now - self.last

        # Check if we would have enough tokens
        potential_tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)

        if potential_tokens >= 1.0:
            # Update state and consume token
            self.last = now
            self.tokens = potential_tokens - 1.0
            return True

        return False

    def get_wait_time(self) -> float:
        """Get estimated wait time until next token available.

        Returns:
            Wait time in seconds (0 if token available now)
        """
        now = time.monotonic()
        elapsed = now - self.last

        potential_tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)

        if potential_tokens >= 1.0:
            return 0.0

        deficit = 1.0 - potential_tokens
        return deficit / self.rate_per_sec

    def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        self.tokens = float(self.capacity)
        self.last = time.monotonic()
        logger.debug("RateLimiter reset")


def parse_rate_string(rate_str: str) -> float:
    """Parse a rate string like "10/min" or "5/sec" into requests per minute.

    Args:
        rate_str: Rate string (e.g., "10/min", "5/sec", "60/hour")

    Returns:
        Requests per minute as float

    Raises:
        ValueError: If rate string is invalid

    Examples:
        >>> parse_rate_string("10/min")
        10.0
        >>> parse_rate_string("5/sec")
        300.0
        >>> parse_rate_string("60/hour")
        1.0
    """
    rate_str = rate_str.strip().lower()

    if "/" not in rate_str:
        raise ValueError(f"Invalid rate string: {rate_str}. Expected format: '10/min'")

    try:
        value_str, unit = rate_str.split("/")
        value = float(value_str)

        # Convert to requests per minute
        if unit in ("min", "minute", "minutes"):
            return value
        elif unit in ("sec", "second", "seconds", "s"):
            return value * 60
        elif unit in ("hour", "hours", "h", "hr"):
            return value / 60
        else:
            raise ValueError(f"Unknown time unit: {unit}")

    except (ValueError, AttributeError) as e:
        raise ValueError(
            f"Invalid rate string: {rate_str}. "
            f"Expected format like '10/min', '5/sec', or '60/hour'"
        ) from e


class GlobalRateLimiter:
    """Global rate limiter for multi-adapter scenarios.

    Tracks rate limits across multiple adapters sharing the same quota.
    Useful for enterprise accounts with shared rate limits.
    """

    def __init__(self, rate_per_minute: float, burst: int = 1):
        """Initialize global rate limiter.

        Args:
            rate_per_minute: Global rate limit
            burst: Burst size
        """
        self.limiter = RateLimiter(rate_per_minute, burst)
        self._adapters: set[str] = set()

    def register_adapter(self, adapter_name: str) -> None:
        """Register an adapter to use this global limiter.

        Args:
            adapter_name: Name of the adapter
        """
        self._adapters.add(adapter_name)
        logger.info(f"Registered adapter '{adapter_name}' with global rate limiter")

    def acquire(self, adapter_name: str | None = None) -> float:
        """Acquire a token for any adapter.

        Args:
            adapter_name: Optional adapter name for logging

        Returns:
            Wait time in seconds
        """
        if adapter_name:
            logger.debug(f"Acquiring token for adapter: {adapter_name}")
        return self.limiter.acquire()

    def get_registered_adapters(self) -> list[str]:
        """Get list of registered adapters.

        Returns:
            List of adapter names
        """
        return sorted(self._adapters)
