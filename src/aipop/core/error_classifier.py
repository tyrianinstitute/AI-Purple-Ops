"""Error classification to prevent false positives.

Maps exceptions to proper categories: infrastructure errors are NOT security findings.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Infrastructure error exceptions (NOT security findings)
INFRA_ERRORS = (
    "RetryError",
    "APIConnectionError",
    "AuthenticationError",
    "TimeoutError",
    "RateLimitError",
    "ConnectionError",
    "ConnectError",  # httpx
    "ReadTimeout",  # httpx
    "WriteTimeout",  # httpx
    "PoolTimeout",  # httpx
    "HTTPStatusError",  # httpx 4xx/5xx
    "RequestError",  # generic request failures
    "SSLError",
    "ProxyError",
    "InvalidURL",
    "TooManyRedirects",
)


def classify_exception(exc: BaseException) -> tuple[str, str, str]:
    """Classify an exception into status, category, and error name.

    Args:
        exc: The exception to classify

    Returns:
        Tuple of (status, category, error_name)
        - status: "error" | "failed" | "blocked"
        - category: "infrastructure_error" | "policy_violation" | "security_finding"
        - error_name: Exception class name or descriptive name

    Raises:
        The exception if it's not a known infrastructure error (unknown errors propagate)
    """
    from .test_result import Category, Status

    name = exc.__class__.__name__

    # Check if it's a known infrastructure error
    if name in INFRA_ERRORS:
        logger.debug(f"Classified {name} as infrastructure error")
        return (
            Status.ERROR.value,
            Category.INFRASTRUCTURE_ERROR.value,
            name,
        )

    # Detect API key misconfiguration
    exc_str = str(exc).lower()
    if isinstance(exc, ValueError) and ("api key" in exc_str or "api_key" in exc_str):
        logger.warning("Detected missing/invalid API key")
        return (
            Status.ERROR.value,
            Category.INFRASTRUCTURE_ERROR.value,
            "MissingApiKey",
        )

    # Detect authentication/authorization errors from error messages
    if "unauthorized" in exc_str or "forbidden" in exc_str or "401" in exc_str or "403" in exc_str:
        logger.warning(f"Detected auth error: {name}")
        return (
            Status.ERROR.value,
            Category.INFRASTRUCTURE_ERROR.value,
            f"AuthError_{name}",
        )

    # Detect quota/rate limit errors from messages
    if (
        "quota" in exc_str
        or "rate limit" in exc_str
        or "too many requests" in exc_str
        or "429" in exc_str
    ):
        logger.warning(f"Detected quota/rate limit error: {name}")
        return (
            Status.ERROR.value,
            Category.INFRASTRUCTURE_ERROR.value,
            f"QuotaExceeded_{name}",
        )

    # Unknown exception - propagate so we notice and can add to INFRA_ERRORS if needed
    logger.error(f"Unknown exception type: {name} - {exc}")
    raise exc


def is_infrastructure_error(exc: BaseException) -> bool:
    """Check if an exception is an infrastructure error.

    Args:
        exc: The exception to check

    Returns:
        True if this is an infrastructure error, False otherwise
    """
    try:
        status, category, _ = classify_exception(exc)
        return category == "infrastructure_error"
    except:
        # If classify_exception raises, it's NOT an infra error
        return False


def get_error_message(exc: BaseException) -> str:
    """Get a user-friendly error message from an exception.

    Args:
        exc: The exception

    Returns:
        User-friendly error message with remediation hints
    """
    name = exc.__class__.__name__

    if name == "AuthenticationError" or "unauthorized" in str(exc).lower():
        return (
            f"Authentication failed: {exc}. "
            "Check that your API key is valid and has the required permissions."
        )

    if name in ("TimeoutError", "ReadTimeout", "WriteTimeout"):
        return (
            f"Request timed out: {exc}. "
            "The API may be slow or unreachable. Try increasing timeout or checking network."
        )

    if "rate limit" in str(exc).lower() or "429" in str(exc):
        return (
            f"Rate limit exceeded: {exc}. "
            "Reduce request rate with --max-rate flag or wait before retrying."
        )

    if "api key" in str(exc).lower():
        return (
            f"API key error: {exc}. "
            "Set the appropriate environment variable (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc)."
        )

    # Generic message
    return f"{name}: {exc}"
