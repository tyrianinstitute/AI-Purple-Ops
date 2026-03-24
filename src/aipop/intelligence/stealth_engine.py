"""Stealth engine for avoiding WAF/rate-limit detection.

Provides:
- Rate limiting (token bucket algorithm)
- Random delays between requests
- User-Agent randomization
- Header randomization
- Request timing analysis
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StealthConfig:
    """Configuration for stealth controls.

    Attributes:
        max_rate: Maximum request rate (e.g., "10/min", "1/5s")
        random_delay_min: Minimum random delay in seconds
        random_delay_max: Maximum random delay in seconds
        randomize_user_agent: Whether to randomize User-Agent headers
        randomize_headers: Whether to randomize other headers
        enabled: Whether stealth mode is enabled
    """

    max_rate: str | None = None  # e.g., "10/min", "1/5s"
    random_delay_min: float = 1.0
    random_delay_max: float = 3.0
    randomize_user_agent: bool = True
    randomize_headers: bool = False
    enabled: bool = False


class TokenBucket:
    """Token bucket algorithm for rate limiting.

    Allows bursts while maintaining average rate limit.

    Example:
        >>> bucket = TokenBucket(rate=10, per_seconds=60)  # 10 requests per minute
        >>> bucket.consume()  # Returns True if token available
    """

    def __init__(self, rate: int, per_seconds: float) -> None:
        """Initialize token bucket.

        Args:
            rate: Number of tokens
            per_seconds: Time period in seconds
        """
        self.rate = rate
        self.per_seconds = per_seconds
        self.tokens = float(rate)
        self.last_update = time.time()
        self.lock = None  # For thread safety if needed

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were available and consumed
        """
        now = time.time()

        # Refill tokens based on time passed
        time_passed = now - self.last_update
        self.tokens = min(self.rate, self.tokens + (time_passed * (self.rate / self.per_seconds)))
        self.last_update = now

        # Try to consume
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False

    def wait_time(self) -> float:
        """Calculate how long to wait for next token.

        Returns:
            Wait time in seconds
        """
        if self.tokens >= 1:
            return 0.0

        tokens_needed = 1 - self.tokens
        return tokens_needed / (self.rate / self.per_seconds)


class StealthEngine:
    """Manages stealth controls to avoid WAF/rate-limit detection.

    Features:
    - Token bucket rate limiting
    - Random delays
    - User-Agent randomization
    - Request timing to appear human

    Example:
        >>> config = StealthConfig(max_rate="10/min", random_delay_min=1, random_delay_max=5)
        >>> engine = StealthEngine(config)
        >>>
        >>> # Before each request
        >>> engine.wait_if_needed()
        >>> headers = engine.get_stealth_headers(base_headers)
    """

    # Common User-Agent strings for randomization
    USER_AGENTS = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Chrome on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Firefox on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]

    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,es;q=0.8",
        "en-US,en;q=0.9,fr;q=0.8",
    ]

    def __init__(self, config: StealthConfig | None = None) -> None:
        """Initialize stealth engine.

        Args:
            config: Stealth configuration
        """
        self.config = config or StealthConfig()

        # Initialize rate limiter if configured
        self.rate_limiter: TokenBucket | None = None
        if self.config.max_rate:
            self.rate_limiter = self._parse_rate_limit(self.config.max_rate)

        # Track request timing
        self.last_request_time: float | None = None

        logger.info(
            f"Stealth engine initialized: enabled={self.config.enabled}, rate={self.config.max_rate}"
        )

    def _parse_rate_limit(self, rate_str: str) -> TokenBucket:
        """Parse rate limit string to TokenBucket.

        Args:
            rate_str: Rate limit string (e.g., "10/min", "1/5s")

        Returns:
            TokenBucket instance
        """
        parts = rate_str.split("/")
        if len(parts) != 2:
            raise ValueError(
                f"Invalid rate format: {rate_str}. Expected 'N/period' (e.g., '10/min')"
            )

        rate = int(parts[0])
        period_str = parts[1].lower()

        # Convert period to seconds
        if period_str.endswith("s"):
            seconds = float(period_str[:-1])
        elif period_str in ("min", "minute"):
            seconds = 60.0
        elif period_str in ("h", "hour"):
            seconds = 3600.0
        else:
            raise ValueError(f"Unknown period: {period_str}. Use 's', 'min', or 'h'")

        logger.info(f"Rate limit configured: {rate} requests per {seconds}s")
        return TokenBucket(rate=rate, per_seconds=seconds)

    def wait_if_needed(self) -> None:
        """Blocks until rate limit allows next request and applies random delay."""
        if not self.config.enabled:
            return

        # Wait for rate limiter
        if self.rate_limiter:
            while not self.rate_limiter.consume():
                wait_time = self.rate_limiter.wait_time()
                logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                time.sleep(wait_time)

        # Apply random delay
        if self.config.random_delay_min > 0 or self.config.random_delay_max > 0:
            delay = random.uniform(self.config.random_delay_min, self.config.random_delay_max)
            logger.debug(f"Applying random delay: {delay:.2f}s")
            time.sleep(delay)

        self.last_request_time = time.time()

    def get_stealth_headers(self, base_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Get randomized headers for stealth.

        Args:
            base_headers: Base headers to augment

        Returns:
            Headers dict with randomizations applied
        """
        headers = dict(base_headers) if base_headers else {}

        if not self.config.enabled:
            return headers

        # Randomize User-Agent
        if self.config.randomize_user_agent and "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(self.USER_AGENTS)

        # Randomize other headers
        if self.config.randomize_headers:
            # Add realistic headers
            if "Accept-Language" not in headers:
                headers["Accept-Language"] = random.choice(self.ACCEPT_LANGUAGES)

            if "Accept" not in headers:
                headers["Accept"] = (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                )

            if "Accept-Encoding" not in headers:
                headers["Accept-Encoding"] = "gzip, deflate, br"

            # Vary DNT header randomly
            if random.random() > 0.5:
                headers["DNT"] = "1"

        return headers

    def get_statistics(self) -> dict[str, Any]:
        """Get stealth engine statistics.

        Returns:
            Statistics dict
        """
        stats = {
            "enabled": self.config.enabled,
            "rate_limit": self.config.max_rate,
            "random_delay_range": f"{self.config.random_delay_min}-{self.config.random_delay_max}s",
        }

        if self.rate_limiter:
            stats["tokens_available"] = int(self.rate_limiter.tokens)
            stats["wait_time"] = self.rate_limiter.wait_time()

        return stats

    @classmethod
    def from_cli_args(
        cls,
        max_rate: str | None = None,
        random_delay: str | None = None,  # e.g., "1-5"
        stealth: bool = False,
        random_user_agent: bool = False,
    ) -> StealthEngine:
        """Create stealth engine from CLI arguments.

        Args:
            max_rate: Max rate string (e.g., "10/min")
            random_delay: Delay range (e.g., "1-5")
            stealth: Enable stealth mode
            random_user_agent: Randomize User-Agent

        Returns:
            StealthEngine instance
        """
        config = StealthConfig(enabled=stealth or bool(max_rate))

        if max_rate:
            config.max_rate = max_rate

        if random_delay:
            parts = random_delay.split("-")
            if len(parts) == 2:
                config.random_delay_min = float(parts[0])
                config.random_delay_max = float(parts[1])

        if random_user_agent or stealth:
            config.randomize_user_agent = True

        if stealth:
            config.randomize_headers = True

        return cls(config)
