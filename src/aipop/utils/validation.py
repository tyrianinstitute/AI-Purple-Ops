"""Input validation framework for CLI arguments."""

from __future__ import annotations

from aipop.utils.errors import HarnessError


class ValidationError(HarnessError):
    """Error raised when input validation fails."""


VALID_FORMATS = {"json", "junit", "both"}
VALID_RESPONSE_MODES = {"echo", "refuse", "random", "smart"}


def validate_format(value: str) -> str:
    """Validate --format option value.

    Args:
        value: Format value to validate

    Returns:
        Validated format value

    Raises:
        ValidationError: If format is invalid
    """
    if value not in VALID_FORMATS:
        valid_options = ", ".join(sorted(VALID_FORMATS))
        raise ValidationError(f"Invalid format: '{value}'. Must be one of: {valid_options}")
    return value


def validate_response_mode(value: str) -> str:
    """Validate --response-mode option value.

    Args:
        value: Response mode value to validate

    Returns:
        Validated response mode value

    Raises:
        ValidationError: If response mode is invalid
    """
    if value not in VALID_RESPONSE_MODES:
        valid_options = ", ".join(sorted(VALID_RESPONSE_MODES))
        raise ValidationError(f"Invalid response mode: '{value}'. Must be one of: {valid_options}")
    return value
