"""Enhanced error handling with root cause extraction for better UX.

Real red teamers need clear error messages, not cryptic RetryError[RuntimeError].
"""

from __future__ import annotations

import re


def extract_root_cause(error: Exception) -> tuple[str, str, str]:
    """Extract root cause from nested exceptions.

    Args:
        error: The exception to analyze

    Returns:
        Tuple of (error_type, error_message, helpful_suggestion)
    """
    # Walk the exception chain to find the root cause
    root = error
    while hasattr(root, "__cause__") and root.__cause__:
        root = root.__cause__

    # Also check __context__ (implicit exception chaining)
    if not hasattr(root, "__cause__") and hasattr(error, "__context__") and error.__context__:
        context = error.__context__
        while hasattr(context, "__context__") and context.__context__:
            context = context.__context__
        if context and not isinstance(context, type(root)):
            root = context

    error_type = type(root).__name__
    error_msg = str(root)

    # Pattern matching for common errors

    # Authentication errors
    if any(
        phrase in error_msg.lower()
        for phrase in [
            "invalid api key",
            "incorrect api key",
            "unauthorized",
            "authentication failed",
            "401",
            "api key",
            "invalid_api_key",
        ]
    ):
        return (
            "AuthenticationError",
            "Invalid or missing API key",
            "Check your API key: export OPENAI_API_KEY='sk-...'",
        )

    # Rate limiting
    if any(
        phrase in error_msg.lower()
        for phrase in ["rate limit", "too many requests", "429", "quota exceeded"]
    ):
        return (
            "RateLimitError",
            "API rate limit exceeded",
            "Wait a few seconds or reduce --streams/--parallel",
        )

    # Model not found
    if any(
        phrase in error_msg.lower()
        for phrase in ["model not found", "invalid model", "model does not exist", "404"]
    ):
        return (
            "ModelNotFoundError",
            "Model not found or not accessible",
            "Check model name and your API access level",
        )

    # Network errors
    if any(
        phrase in error_msg.lower()
        for phrase in [
            "connection error",
            "network error",
            "connection refused",
            "timeout",
            "failed to establish",
            "name or service not known",
        ]
    ):
        return (
            "NetworkError",
            "Network connection failed",
            "Check your internet connection and firewall settings",
        )

    # Insufficient credits/quota
    if any(
        phrase in error_msg.lower()
        for phrase in ["insufficient", "quota", "credits", "billing", "payment required"]
    ):
        return (
            "InsufficientQuotaError",
            "Insufficient API credits or quota",
            "Add credits to your API account or check billing",
        )

    # Permission/access errors
    if any(
        phrase in error_msg.lower()
        for phrase in ["permission denied", "access denied", "forbidden", "403"]
    ):
        return (
            "PermissionError",
            "Access denied to this resource",
            "Check your API key permissions and model access",
        )

    # Invalid request/parameter errors
    if any(
        phrase in error_msg.lower()
        for phrase in ["invalid request", "bad request", "400", "invalid parameter"]
    ):
        return (
            "InvalidRequestError",
            f"Invalid API request: {error_msg[:100]}",
            "Check your request parameters",
        )

    # GPU/CUDA errors
    if any(
        phrase in error_msg.lower()
        for phrase in ["cuda", "out of memory", "gpu", "device-side assert"]
    ):
        return (
            "GPUError",
            "GPU error or out of memory",
            "Reduce batch size or use CPU: --device cpu",
        )

    # Import errors (missing dependencies)
    if error_type in ["ImportError", "ModuleNotFoundError"]:
        module_match = re.search(r"No module named '([^']+)'", error_msg)
        module = module_match.group(1) if module_match else "unknown"
        return (
            "DependencyError",
            f"Missing dependency: {module}",
            f"Install with: pip install {module} or aipop plugins install <method>",
        )

    # Generic fallback
    return (
        error_type,
        error_msg[:200] if len(error_msg) > 200 else error_msg,
        "Check logs for full traceback",
    )


def format_error_message(error: Exception, context: str = "") -> str:
    """Format error with root cause analysis.

    Args:
        error: The exception
        context: Additional context about what was being attempted

    Returns:
        Formatted error message for display
    """
    error_type, error_msg, suggestion = extract_root_cause(error)

    parts = []
    if context:
        parts.append(f"[FAILED] {context}")
    parts.append(f"[ERROR] {error_type}: {error_msg}")
    parts.append(f"[HELP] {suggestion}")

    return "\n".join(parts)


def is_retryable_error(error: Exception) -> bool:
    """Determine if an error is likely retryable.

    Args:
        error: The exception

    Returns:
        True if the error should be retried
    """
    error_type, error_msg, _ = extract_root_cause(error)

    # Retryable: transient network issues, rate limits
    retryable_types = {"RateLimitError", "NetworkError"}
    retryable_phrases = ["timeout", "connection error", "503", "502"]

    if error_type in retryable_types:
        return True

    if any(phrase in error_msg.lower() for phrase in retryable_phrases):
        return True

    return False


def get_error_category(error: Exception) -> str:
    """Categorize error for metrics/logging.

    Args:
        error: The exception

    Returns:
        Error category string
    """
    error_type, _, _ = extract_root_cause(error)

    categories = {
        "AuthenticationError": "auth",
        "RateLimitError": "rate_limit",
        "NetworkError": "network",
        "GPUError": "hardware",
        "DependencyError": "dependency",
        "ModelNotFoundError": "config",
        "InvalidRequestError": "config",
    }

    return categories.get(error_type, "unknown")
