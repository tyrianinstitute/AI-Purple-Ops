"""Dependency checking utilities for optional features."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass


@dataclass
class DependencyStatus:
    """Status of dependency check."""

    available: bool
    missing_packages: list[str]
    error_message: str | None = None


def check_adversarial_dependencies() -> DependencyStatus:
    """Check if adversarial dependencies are installed.

    Returns:
        DependencyStatus with availability and missing packages
    """
    required_packages = {
        "nanogcg": "nanogcg",
        "transformers": "transformers",
        "accelerate": "accelerate",
    }

    missing = []
    for package_name, import_name in required_packages.items():
        if importlib.util.find_spec(import_name) is None:
            missing.append(package_name)

    if missing:
        error_msg = (
            f"GCG requires adversarial dependencies. Missing: {', '.join(missing)}\n"
            f"Install with: pip install aipurpleops[adversarial]"
        )
        return DependencyStatus(available=False, missing_packages=missing, error_message=error_msg)

    return DependencyStatus(available=True, missing_packages=[])


def check_torch_available() -> bool:
    """Check if PyTorch is available.

    Returns:
        True if torch is installed, False otherwise
    """
    return importlib.util.find_spec("torch") is not None


def check_package_available(package_name: str) -> bool:
    """Check if a specific package is available.

    Args:
        package_name: Name of the package to check

    Returns:
        True if package is installed, False otherwise
    """
    return importlib.util.find_spec(package_name) is not None


def get_installation_command(feature: str = "adversarial") -> str:
    """Get installation command for a feature.

    Args:
        feature: Feature name ("adversarial", "cloud", "local", etc.)

    Returns:
        Installation command string
    """
    if feature == "adversarial":
        return "pip install aipurpleops[adversarial]"
    elif feature == "cloud":
        return "pip install aipurpleops[cloud]"
    elif feature == "local":
        return "pip install aipurpleops[local]"
    elif feature == "all":
        return "pip install aipurpleops[all-adapters]"
    else:
        return f"pip install aipurpleops[{feature}]"
