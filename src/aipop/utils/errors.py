from __future__ import annotations


class HarnessError(RuntimeError):
    """Base error for the harness."""


class ConfigError(HarnessError):
    """Configuration problem detected."""


class PreflightError(HarnessError):
    """Preflight checks failed."""


class EnvVarMissingError(HarnessError):
    """A required environment variable is missing."""
