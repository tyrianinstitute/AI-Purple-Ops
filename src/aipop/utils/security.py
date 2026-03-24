"""Security utilities for input validation and sanitization."""

from __future__ import annotations

from pathlib import Path
from aipop.utils.paths import get_package_data_path

from aipop.utils.errors import HarnessError


class SecurityError(HarnessError):
    """Security validation error."""


# Define allowed base directories for different file types
ALLOWED_SUITE_DIRS = [
    get_package_data_path("suites"),  # Primary suite directory
    Path("."),  # Current working directory (for development/testing)
    Path("/tmp"),  # Temporary directory (for testing)
]

ALLOWED_CONFIG_DIRS = [
    Path("."),  # Current working directory
    Path.home() / ".config" / "ai-purple-ops",  # User config directory
    Path("/etc/ai-purple-ops"),  # System config directory
    Path("/tmp"),  # Temporary directory (for testing)
]


def validate_suite_path(path: str | Path) -> Path:
    """Validate and resolve a suite path to prevent path traversal attacks.

    Args:
        path: Path to validate (can be relative or absolute)

    Returns:
        Resolved absolute path if valid

    Raises:
        SecurityError: If path is outside allowed directories or contains suspicious patterns
    """
    path = Path(path)

    # Check for obvious path traversal patterns
    path_str = str(path)
    if ".." in path.parts or path_str.startswith("/"):
        # For absolute paths, check if they resolve to allowed locations
        if path.is_absolute():
            resolved = path.resolve()
            # Check if path is within any allowed directory
            for allowed_dir in ALLOWED_SUITE_DIRS:
                try:
                    allowed_resolved = allowed_dir.resolve()
                    if resolved == allowed_resolved or resolved.is_relative_to(allowed_resolved):
                        return resolved
                except (ValueError, OSError):
                    continue
            # If we get here, path is absolute but not in allowed dirs
            raise SecurityError(
                f"Suite path outside allowed directories: {path}\n"
                f"Hint: Suites must be in 'suites/' or current directory."
            )

    # For relative paths, resolve and validate
    try:
        resolved = path.resolve()
    except (ValueError, OSError) as e:
        raise SecurityError(f"Invalid suite path: {path}\nError: {e}") from e

    # Check if resolved path is within any allowed directory
    for allowed_dir in ALLOWED_SUITE_DIRS:
        try:
            allowed_resolved = allowed_dir.resolve()
            if resolved == allowed_resolved or resolved.is_relative_to(allowed_resolved):
                return resolved
        except (ValueError, OSError):
            continue

    # Path is outside all allowed directories
    raise SecurityError(
        f"Suite path outside allowed directories: {path}\n"
        f"Resolved to: {resolved}\n"
        f"Hint: Suites must be in 'suites/' or current directory."
    )


def validate_config_path(path: str | Path) -> Path:
    """Validate and resolve a config file path.

    Args:
        path: Path to validate

    Returns:
        Resolved absolute path if valid

    Raises:
        SecurityError: If path is outside allowed directories
    """
    path = Path(path)

    # Resolve path
    try:
        resolved = path.resolve()
    except (ValueError, OSError) as e:
        raise SecurityError(f"Invalid config path: {path}\nError: {e}") from e

    # Check if resolved path is within any allowed directory
    for allowed_dir in ALLOWED_CONFIG_DIRS:
        try:
            allowed_resolved = allowed_dir.resolve()
            if resolved == allowed_resolved or resolved.is_relative_to(allowed_resolved):
                return resolved
        except (ValueError, OSError):
            continue

    # Path is outside all allowed directories
    raise SecurityError(
        f"Config path outside allowed directories: {path}\n"
        f"Resolved to: {resolved}\n"
        f"Hint: Configs must be in current directory, ~/.config/ai-purple-ops/, or /etc/ai-purple-ops/"
    )


def validate_seed(seed: int | str) -> int:
    """Validate seed value for deterministic randomness.

    Args:
        seed: Seed value to validate

    Returns:
        Validated seed as integer

    Raises:
        SecurityError: If seed is invalid or outside safe bounds
    """
    try:
        seed_int = int(seed)
    except (ValueError, TypeError) as e:
        raise SecurityError(
            f"Invalid seed value: {seed}\nHint: Seed must be an integer between 0 and 2^32-1"
        ) from e

    # Validate bounds (0 to 2^32-1 is safe for Python's random module)
    if not 0 <= seed_int <= 4294967295:  # 2^32 - 1
        raise SecurityError(
            f"Seed value out of bounds: {seed_int}\n"
            f"Hint: Seed must be between 0 and 4294967295 (2^32-1)"
        )

    return seed_int


def sanitize_env_var(value: str, var_name: str, max_length: int = 1024) -> str:
    """Sanitize environment variable value.

    Args:
        value: Value to sanitize
        var_name: Name of the environment variable (for error messages)
        max_length: Maximum allowed length

    Returns:
        Sanitized value

    Raises:
        SecurityError: If value contains suspicious patterns or exceeds length
    """
    if not isinstance(value, str):
        raise SecurityError(
            f"Invalid environment variable {var_name}: Expected string, got {type(value).__name__}"
        )

    # Check length
    if len(value) > max_length:
        raise SecurityError(
            f"Environment variable {var_name} exceeds maximum length of {max_length} characters"
        )

    # Check for null bytes (common injection vector)
    if "\x00" in value:
        raise SecurityError(f"Environment variable {var_name} contains null bytes (security risk)")

    # Check for common injection patterns (command substitution, path traversal)
    suspicious_patterns = [
        ("$(", "Command substitution"),
        ("`", "Command substitution"),
        ("../", "Path traversal"),
        ("..\\", "Path traversal"),
    ]

    for pattern, description in suspicious_patterns:
        if pattern in value:
            raise SecurityError(
                f"Environment variable {var_name} contains suspicious pattern: {description}\n"
                f"Value: {value[:100]}..."
            )

    return value


def validate_output_path(path: str | Path, base_dir: Path | None = None) -> Path:
    """Validate output path for reports, transcripts, etc.

    Args:
        path: Path to validate
        base_dir: Optional base directory to resolve relative paths against

    Returns:
        Resolved absolute path if valid

    Raises:
        SecurityError: If path is suspicious or cannot be created
    """
    path = Path(path)

    # If relative and base_dir provided, resolve against base_dir
    if not path.is_absolute() and base_dir:
        path = base_dir / path

    # Resolve path
    try:
        resolved = path.resolve()
    except (ValueError, OSError) as e:
        raise SecurityError(f"Invalid output path: {path}\nError: {e}") from e

    # Check for path traversal out of project directory
    cwd = Path.cwd().resolve()
    try:
        # Allow paths within current working directory
        if resolved.is_relative_to(cwd):
            return resolved
    except (ValueError, AttributeError):
        pass

    # Also allow /tmp for temporary files
    try:
        if resolved.is_relative_to(Path("/tmp")):
            return resolved
    except (ValueError, AttributeError):
        pass

    # Path is outside safe locations
    raise SecurityError(
        f"Output path outside safe directories: {path}\n"
        f"Resolved to: {resolved}\n"
        f"Hint: Output paths must be within current directory or /tmp"
    )
