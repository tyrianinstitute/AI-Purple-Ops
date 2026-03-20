"""Profiles — saved configuration sets for different workflows.

A profile is a named set of workspace option overrides. Load a profile
to configure the tool for a specific workflow without typing flags.

Built-in profiles:
  pentest  — Burp proxy, verbose, evidence capture, real adapter
  bounty   — aggressive, budget-capped, evidence for submission
  lab      — static adapter, learning mode, verbose for understanding
  ci       — quiet, JSON output, fail-fast, no interactive prompts

Custom profiles: ~/.aipop/profiles/<name>.json
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PROFILES_DIR = Path.home() / ".aipop" / "profiles"


@dataclass
class Profile:
    """A named configuration preset."""

    name: str
    description: str
    options: dict[str, Any]


# Built-in profiles — opinionated defaults for common workflows
BUILTIN_PROFILES = {
    "pentest": Profile(
        name="pentest",
        description="Pentester workflow — proxy through Burp, verbose output, evidence capture",
        options={
            "PROXY": "http://127.0.0.1:8080",
            "VERBOSE": True,
            "CAPTURE_TRAFFIC": True,
        },
    ),
    "bounty": Profile(
        name="bounty",
        description="Bug bounty — budget-capped, evidence for submission",
        options={
            "BUDGET": 2.00,
            "VERBOSE": True,
        },
    ),
    "lab": Profile(
        name="lab",
        description="Academy lab — static adapter, verbose for learning",
        options={
            "ADAPTER": "static",
            "RESPONSE_MODE": "smart",
            "VERBOSE": True,
        },
    ),
    "ci": Profile(
        name="ci",
        description="CI/CD pipeline — quiet, JSON output, no prompts",
        options={
            "RESPONSE_MODE": "smart",
        },
    ),
}


def list_profiles() -> list[Profile]:
    """List all profiles — built-in + custom."""
    profiles = list(BUILTIN_PROFILES.values())

    # Load custom profiles from ~/.aipop/profiles/
    if PROFILES_DIR.exists():
        for path in sorted(PROFILES_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text())
                profiles.append(Profile(
                    name=path.stem,
                    description=data.get("description", "Custom profile"),
                    options=data.get("options", {}),
                ))
            except Exception as e:
                log.warning(f"Failed to load profile {path}: {e}")

    return profiles


def load_profile(name: str) -> Profile:
    """Load a profile by name.

    Checks built-in profiles first, then custom profiles in ~/.aipop/profiles/.

    Raises:
        KeyError: If profile not found
    """
    # Built-in
    if name in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[name]

    # Custom
    custom_path = PROFILES_DIR / f"{name}.json"
    if custom_path.exists():
        data = json.loads(custom_path.read_text())
        return Profile(
            name=name,
            description=data.get("description", "Custom profile"),
            options=data.get("options", {}),
        )

    available = ", ".join(
        sorted(set(list(BUILTIN_PROFILES.keys()) + [
            p.stem for p in PROFILES_DIR.glob("*.json")
        ] if PROFILES_DIR.exists() else list(BUILTIN_PROFILES.keys())))
    )
    raise KeyError(f"Profile not found: {name}. Available: {available}")


def save_profile(name: str, description: str, options: dict[str, Any]) -> Path:
    """Save a custom profile to ~/.aipop/profiles/.

    Args:
        name: Profile name (alphanumeric + hyphens)
        description: One-line description
        options: Option key-value pairs to save

    Returns:
        Path to the saved profile file
    """
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    path = PROFILES_DIR / f"{name}.json"
    path.write_text(
        json.dumps(
            {"name": name, "description": description, "options": options},
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def apply_profile(profile: Profile, workspace: Any) -> list[str]:
    """Apply a profile's options to a workspace.

    Returns list of options that were set.
    """
    applied = []
    for key, value in profile.options.items():
        try:
            workspace.set(key, value, source="profile")
            applied.append(f"{key}={value}")
        except KeyError:
            log.warning(f"Profile option {key} not recognized, skipping")
    return applied
