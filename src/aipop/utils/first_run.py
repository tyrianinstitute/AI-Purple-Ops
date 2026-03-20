"""First-run detection and user preference management.

Detects if this is the user's first time running aipop and manages
their implementation preferences (official vs legacy).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def get_config_path() -> Path:
    """Get path to user configuration file.

    Returns:
        Path to ~/.aipop/config.yaml
    """
    return Path.home() / ".aipop" / "config.yaml"


def is_first_run() -> bool:
    """Check if this is user's first run.

    Returns:
        True if config file doesn't exist (first run)
    """
    config_path = get_config_path()
    return not config_path.exists()


def get_user_preference() -> dict[str, Any]:
    """Load user preferences from config file.

    Returns:
        Dictionary of user preferences, empty dict if no config exists
    """
    config_path = get_config_path()

    if not config_path.exists():
        return {}

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
        return config
    except Exception as e:
        logger.warning(f"Failed to load config from {config_path}: {e}")
        return {}


def save_user_preference(preference: dict[str, Any]) -> None:
    """Save user preferences to config file.

    Args:
        preference: Dictionary of preferences to save
    """
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Load existing config if it exists
        existing = {}
        if config_path.exists():
            with open(config_path) as f:
                existing = yaml.safe_load(f) or {}

        # Merge with new preferences
        existing.update(preference)

        # Write back
        with open(config_path, "w") as f:
            yaml.dump(existing, f, default_flow_style=False)

        logger.info(f"Saved user preferences to {config_path}")
    except Exception as e:
        logger.error(f"Failed to save config to {config_path}: {e}")
        raise


def get_default_implementation() -> str:
    """Get user's preferred default implementation.

    Returns:
        'official', 'legacy', or 'prompt' (ask each time)
    """
    prefs = get_user_preference()
    return prefs.get("default_implementation", "prompt")


def set_default_implementation(implementation: str) -> None:
    """Set user's preferred default implementation.

    Args:
        implementation: 'official', 'legacy', or 'prompt'
    """
    if implementation not in ["official", "legacy", "prompt"]:
        raise ValueError(
            f"Invalid implementation: {implementation}. "
            f"Must be 'official', 'legacy', or 'prompt'"
        )

    save_user_preference({"default_implementation": implementation})


def should_run_setup() -> bool:
    """Check if we should run the setup wizard.

    Returns:
        True if first run OR user has 'prompt' as default
    """
    if is_first_run():
        return True

    return get_default_implementation() == "prompt"


def mark_setup_complete(implementation: str, skip_future: bool = False) -> None:
    """Mark that setup has been completed.

    Args:
        implementation: Which implementation user selected
        skip_future: If True, don't ask again (set default)
    """
    if skip_future:
        set_default_implementation(implementation)
    else:
        # Set to 'prompt' so we ask next time
        set_default_implementation("prompt")

    # Also save last setup date
    from datetime import datetime

    save_user_preference(
        {
            "last_setup": datetime.now().isoformat(),
            "setup_completed": True,
        }
    )
