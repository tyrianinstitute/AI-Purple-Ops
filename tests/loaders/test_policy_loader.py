"""Tests for policy loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.loaders.policy_loader import (
    PolicyConfig,
    PolicyLoadError,
    load_policy,
)


@pytest.fixture
def temp_policy_dir(tmp_path: Path) -> Path:
    """Create temporary policy directory."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    return policy_dir


@pytest.fixture
def content_policy_file(temp_policy_dir: Path) -> Path:
    """Create a valid content policy file."""
    policy_file = temp_policy_dir / "content_policy.yaml"
    policy_file.write_text(
        """
version: "1.0.0"
description: Test policy for content detection
rules:
  - id: test_rule_1
    category: violence
    severity: high
    description: Test rule 1
    patterns:
      - "bad_pattern"
    keywords:
      - "bad_word"
thresholds: {}
"""
    )
    return policy_file


@pytest.fixture
def tool_policy_file(temp_policy_dir: Path) -> Path:
    """Create a valid tool policy file."""
    policy_file = temp_policy_dir / "tool_policy.yaml"
    policy_file.write_text(
        """
version: "1.0.0"
description: Test policy for tool usage
allowed_tools:
  - "tool_a"
  - "tool_b"
schema: {}
"""
    )
    return policy_file


class TestPolicyLoader:
    """Test policy loading functionality."""

    def test_load_content_policy(self, content_policy_file: Path) -> None:
        """Test loading a content policy file."""
        policy_config = load_policy(content_policy_file)

        assert policy_config.content_policy is not None
        assert policy_config.content_policy.version == "1.0.0"
        assert len(policy_config.content_policy.rules) == 1
        # Policy loader uses 'id' field and maps to rule_id
        assert policy_config.content_policy.rules[0].rule_id == "test_rule_1"
        assert policy_config.tool_policy is None

    def test_load_tool_policy(self, tool_policy_file: Path) -> None:
        """Test loading a tool policy file."""
        policy_config = load_policy(tool_policy_file)

        assert policy_config.tool_policy is not None
        assert policy_config.tool_policy.version == "1.0.0"
        assert len(policy_config.tool_policy.allowed_tools) == 2
        assert "tool_a" in policy_config.tool_policy.allowed_tools
        assert policy_config.content_policy is None

    def test_load_from_directory(
        self, temp_policy_dir: Path, content_policy_file: Path, tool_policy_file: Path
    ) -> None:
        """Test loading policies from a directory."""
        policy_config = load_policy(temp_policy_dir)

        assert policy_config.content_policy is not None
        assert policy_config.tool_policy is not None

    def test_nonexistent_path_raises_error(self, tmp_path: Path) -> None:
        """Test that nonexistent path raises error."""
        with pytest.raises(PolicyLoadError, match="Policy path not found"):
            load_policy(tmp_path / "nonexistent")

    def test_empty_directory_raises_error(self, temp_policy_dir: Path) -> None:
        """Test that empty directory raises error."""
        with pytest.raises(PolicyLoadError, match="No policy files found"):
            load_policy(temp_policy_dir)

    def test_invalid_yaml_raises_error(self, temp_policy_dir: Path) -> None:
        """Test that invalid YAML raises error."""
        invalid_file = temp_policy_dir / "invalid.yaml"
        invalid_file.write_text("invalid: yaml: content: [")

        with pytest.raises(PolicyLoadError, match="Invalid YAML syntax"):
            load_policy(invalid_file)

    def test_invalid_schema_raises_error(self, temp_policy_dir: Path) -> None:
        """Test that invalid schema raises error."""
        invalid_file = temp_policy_dir / "invalid_schema.yaml"
        invalid_file.write_text(
            """
id: test
rules:
  - rule_id: test
    severity: invalid_severity
    description: Test
"""
        )

        with pytest.raises(PolicyLoadError, match="Missing 'version' field"):
            load_policy(invalid_file)

    def test_missing_required_fields(self, temp_policy_dir: Path) -> None:
        """Test that missing required fields raises error."""
        invalid_file = temp_policy_dir / "missing_fields.yaml"
        invalid_file.write_text("name: Test Policy")

        with pytest.raises(PolicyLoadError, match="Missing 'version' field"):
            load_policy(invalid_file)

    def test_policy_config_defaults(self) -> None:
        """Test PolicyConfig defaults."""
        config = PolicyConfig()
        assert config.content_policy is None
        assert config.tool_policy is None

    def test_content_policy_rule_defaults(self) -> None:
        """Test ContentPolicyRule defaults."""
        from aipop.loaders.policy_loader import ContentPolicyRule

        rule = ContentPolicyRule(
            rule_id="test",
            category="test",
            severity="high",
            description="Test rule",
            patterns=[],
            keywords=[],
        )
        assert rule.patterns == []
        assert rule.keywords == []
