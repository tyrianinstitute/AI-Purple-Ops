"""Installation profiles for AI Purple Ops.

Defines different installation profiles with varying levels of functionality:
- BASIC: Core functionality only (adversarial suffixes, adapters)
- PRO: + PyRIT + Promptfoo (CTF capabilities, multi-turn attacks)
- CUSTOM: User selects individual components
"""

from dataclasses import dataclass
from enum import Enum


class ProfileType(str, Enum):
    """Installation profile types."""

    BASIC = "basic"
    PRO = "pro"
    CUSTOM = "custom"


@dataclass
class InstallProfile:
    """Defines an installation profile with its dependencies and features."""

    name: str
    display_name: str
    description: str
    use_cases: list[str]
    dependencies: list[str]
    disk_size_mb: int
    includes_ctf: bool
    includes_multiturn: bool


# Profile definitions
PROFILES = {
    ProfileType.BASIC: InstallProfile(
        name="basic",
        display_name="Basic",
        description="Core AI Purple Ops functionality for adversarial testing",
        use_cases=[
            "Generate adversarial suffixes (GCG, PAIR, AutoDAN)",
            "Test multiple AI models with 7 production adapters",
            "Run batch vulnerability scans",
            "Generate evidence reports",
            "Guardrail fingerprinting",
        ],
        dependencies=[
            # Already in base requirements.txt
        ],
        disk_size_mb=500,
        includes_ctf=False,
        includes_multiturn=False,
    ),
    ProfileType.PRO: InstallProfile(
        name="pro",
        display_name="Pro (CTF-Ready)",
        description="Full capabilities including CTF attack strategies and multi-turn orchestration",
        use_cases=[
            "All Basic features",
            "CTF objective-based attacks (MCP injection, prompt extraction, etc.)",
            "Multi-turn adaptive attack orchestration",
            "Context-aware intelligent probing",
            "State-machine driven attack strategies",
            "Integration with PyRIT and Promptfoo ecosystems",
        ],
        dependencies=[
            "promptfoo>=0.90.0",  # For attack plugins and strategies
        ],
        disk_size_mb=700,  # PyRIT already in base, Promptfoo ~200MB
        includes_ctf=True,
        includes_multiturn=True,
    ),
}


def get_profile(profile_type: ProfileType | str) -> InstallProfile:
    """Get an installation profile by type.

    Args:
        profile_type: Profile type (BASIC, PRO, or CUSTOM)

    Returns:
        InstallProfile for the requested type

    Raises:
        ValueError: If profile type is invalid
    """
    if isinstance(profile_type, str):
        try:
            profile_type = ProfileType(profile_type.lower())
        except ValueError as e:
            raise ValueError(
                f"Invalid profile type: {profile_type}. Must be one of: {', '.join([p.value for p in ProfileType])}"
            ) from e

    if profile_type not in PROFILES:
        raise ValueError(f"Profile not found: {profile_type}")

    return PROFILES[profile_type]


def list_profiles() -> list[InstallProfile]:
    """List all available installation profiles."""
    return list(PROFILES.values())
