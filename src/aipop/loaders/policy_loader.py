"""Policy configuration loader with schema validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aipop.utils.errors import HarnessError
from aipop.utils.paths import get_package_data_path


class PolicyLoadError(HarnessError):
    """Error loading or parsing policy configuration."""


@dataclass
class ContentPolicyRule:
    """Single content policy rule definition."""

    rule_id: str
    category: str  # "violence", "hate_speech", "sexual_content", "pii", etc.
    severity: str  # "low", "medium", "high", "critical"
    patterns: list[str]  # Regex patterns to match
    keywords: list[str]  # Keywords to detect
    description: str


@dataclass
class ContentPolicyConfig:
    """Content policy configuration."""

    version: str
    description: str
    rules: list[ContentPolicyRule]
    thresholds: dict[str, float]  # SLO thresholds, e.g., {"harmful_output_rate": 0.05}


@dataclass
class ToolPolicyConfig:
    """Tool policy configuration."""

    version: str
    description: str
    allowed_tools: list[str]  # Not yet implemented
    schema: dict[str, Any]  # Not yet implemented


@dataclass
class PolicyConfig:
    """Complete policy configuration."""

    content_policy: ContentPolicyConfig | None = None
    tool_policy: ToolPolicyConfig | None = None


def load_policy(policy_path: str | Path | None = None) -> PolicyConfig:
    """Load policy configuration from YAML file(s).

    If policy_path is None, loads default policies from policies/ directory.
    If policy_path is a directory, loads all YAML files in it.
    If policy_path is a file, loads that specific file.

    Args:
        policy_path: Path to policy file/directory, or None for defaults

    Returns:
        PolicyConfig with loaded policies

    Raises:
        PolicyLoadError: If policy file is invalid or cannot be loaded
    """
    if policy_path is None:
        # Default: load from policies/ directory
        policy_path = get_package_data_path("policies")
    else:
        policy_path = Path(policy_path)

    config = PolicyConfig()

    # If directory, load all YAML files
    if policy_path.is_dir():
        content_policy_file = policy_path / "content_policy.yaml"
        # Check for both tool_allowlist.yaml and tool_policy.yaml
        tool_policy_file = policy_path / "tool_allowlist.yaml"
        if not tool_policy_file.exists():
            tool_policy_file = policy_path / "tool_policy.yaml"

        if content_policy_file.exists():
            config.content_policy = _load_content_policy(content_policy_file)

        if tool_policy_file.exists():
            config.tool_policy = _load_tool_policy(tool_policy_file)

        # If no policy files found in directory, raise error
        if config.content_policy is None and config.tool_policy is None:
            raise PolicyLoadError(
                f"No policy files found in {policy_path}\n"
                f"Expected: content_policy.yaml and/or tool_policy.yaml (or tool_allowlist.yaml)"
            )

        return config

    # If file, determine type and load
    if policy_path.is_file():
        if "content_policy" in policy_path.name.lower():
            config.content_policy = _load_content_policy(policy_path)
        elif "tool" in policy_path.name.lower() or "allowlist" in policy_path.name.lower():
            config.tool_policy = _load_tool_policy(policy_path)
        else:
            # Try to load as content policy by default
            config.content_policy = _load_content_policy(policy_path)

        return config

    # Path doesn't exist
    raise PolicyLoadError(
        f"Policy path not found: {policy_path}\nHint: Check that the path exists and is accessible."
    )


def _load_content_policy(policy_file: Path) -> ContentPolicyConfig:
    """Load content policy from YAML file."""
    try:
        with policy_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyLoadError(
            f"Invalid YAML syntax in {policy_file.name}: {e}\n"
            f"Hint: Check YAML syntax with a validator."
        ) from e
    except Exception as e:
        raise PolicyLoadError(
            f"Failed to read {policy_file.name}: {e}\nHint: Check file permissions and encoding."
        ) from e

    if not isinstance(data, dict):
        raise PolicyLoadError(
            f"Invalid policy format in {policy_file.name}: Expected dict, got {type(data).__name__}\n"
            f"Hint: Policy file should start with 'version:', 'description:', etc."
        )

    # Validate required fields
    if "version" not in data:
        raise PolicyLoadError(
            f"Missing 'version' field in {policy_file.name}\n"
            f"Hint: Add a 'version:' field to the policy file."
        )

    if "rules" not in data:
        raise PolicyLoadError(
            f"Missing 'rules' field in {policy_file.name}\n"
            f"Hint: Add a 'rules:' section with policy rule definitions."
        )

    # Parse rules
    rules: list[ContentPolicyRule] = []
    for rule_data in data.get("rules", []):
        if not isinstance(rule_data, dict):
            continue

        rule = ContentPolicyRule(
            rule_id=rule_data.get("id", f"rule_{len(rules) + 1}"),
            category=rule_data.get("category", "unknown"),
            severity=rule_data.get("severity", "medium"),
            patterns=rule_data.get("patterns", []),
            keywords=rule_data.get("keywords", []),
            description=rule_data.get("description", ""),
        )
        rules.append(rule)

    return ContentPolicyConfig(
        version=data.get("version", "1.0.0"),
        description=data.get("description", ""),
        rules=rules,
        thresholds=data.get("thresholds", {}),
    )


def _load_tool_policy(policy_file: Path) -> ToolPolicyConfig:
    """Load tool policy from YAML file."""
    try:
        with policy_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyLoadError(
            f"Invalid YAML syntax in {policy_file.name}: {e}\n"
            f"Hint: Check YAML syntax with a validator."
        ) from e
    except Exception as e:
        raise PolicyLoadError(
            f"Failed to read {policy_file.name}: {e}\nHint: Check file permissions and encoding."
        ) from e

    if not isinstance(data, dict):
        raise PolicyLoadError(
            f"Invalid policy format in {policy_file.name}: Expected dict, got {type(data).__name__}"
        )

    # TODO: not yet implemented
    return ToolPolicyConfig(
        version=data.get("version", "1.0.0"),
        description=data.get("description", "Tool policy"),
        allowed_tools=data.get("allowed_tools", []),
        schema=data.get("schema", {}),
    )
