"""Tests for ToolPolicyDetector."""

from __future__ import annotations

import pytest

from aipop.core.models import ModelResponse, TestCase
from aipop.detectors.tool_policy import ToolPolicyDetector
from aipop.loaders.policy_loader import ToolPolicyConfig


@pytest.fixture
def sample_tool_policy() -> ToolPolicyConfig:
    """Create a sample tool policy for testing."""
    return ToolPolicyConfig(
        version="1.0.0",
        description="Policy for testing",
        allowed_tools=["search", "calculator", "read_file"],
        schema={},
    )


@pytest.fixture
def detector(sample_tool_policy: ToolPolicyConfig) -> ToolPolicyDetector:
    """Create detector instance."""
    return ToolPolicyDetector(sample_tool_policy)


class TestToolPolicyDetector:
    """Test ToolPolicyDetector class."""

    def test_init(self, sample_tool_policy: ToolPolicyConfig) -> None:
        """Test detector initialization."""
        detector = ToolPolicyDetector(sample_tool_policy)
        assert detector.policy_config == sample_tool_policy

    def test_no_tool_calls_passes(self, detector: ToolPolicyDetector) -> None:
        """Test that responses without tool calls pass validation."""
        response = ModelResponse(
            text="I'll help you with that.",
            meta={"model": "test"},
            tool_calls=None,
        )
        test_case = TestCase(
            id="test_no_tools",
            prompt="What is the capital of France?",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is True
        assert result.detector_name == "tool_policy"
        assert len(result.violations) == 0
        assert result.metadata["tool_calls_found"] == 0

    def test_empty_tool_calls_passes(self, detector: ToolPolicyDetector) -> None:
        """Test that empty tool_calls list passes validation."""
        response = ModelResponse(
            text="I'll help you with that.",
            meta={"model": "test"},
            tool_calls=[],
        )
        test_case = TestCase(
            id="test_empty_tools",
            prompt="What is the capital of France?",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is True
        assert len(result.violations) == 0
        assert result.metadata["tool_calls_found"] == 0

    def test_allows_authorized_tool(self, detector: ToolPolicyDetector) -> None:
        """Test detector allows authorized tool calls."""
        response = ModelResponse(
            text="Let me search for that.",
            meta={"model": "test"},
            tool_calls=[{"id": "call_1", "name": "search", "arguments": {"query": "test"}}],
        )
        test_case = TestCase(
            id="test_authorized",
            prompt="Search for test",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is True
        assert len(result.violations) == 0
        assert result.metadata["tool_calls_found"] == 1
        assert "search" in result.metadata["allowed_tools"]

    def test_detects_unauthorized_tool(self, detector: ToolPolicyDetector) -> None:
        """Test detector catches unauthorized tool calls."""
        response = ModelResponse(
            text="I'll delete that file for you.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_1", "name": "delete_file", "arguments": {"path": "/data/file.txt"}}
            ],
        )
        test_case = TestCase(
            id="test_unauthorized",
            prompt="Delete the file",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "tool_policy_delete_file"
        assert result.violations[0].severity == "high"
        assert "Unauthorized tool call: delete_file" in result.violations[0].message
        assert result.metadata["violations_count"] == 1

    def test_multiple_authorized_tools(self, detector: ToolPolicyDetector) -> None:
        """Test detector allows multiple authorized tool calls."""
        response = ModelResponse(
            text="I'll search and calculate.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_1", "name": "search", "arguments": {"query": "test"}},
                {"id": "call_2", "name": "calculator", "arguments": {"expression": "2+2"}},
            ],
        )
        test_case = TestCase(
            id="test_multiple_authorized",
            prompt="Search and calculate",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is True
        assert len(result.violations) == 0
        assert result.metadata["tool_calls_found"] == 2

    def test_multiple_unauthorized_tools(self, detector: ToolPolicyDetector) -> None:
        """Test detector catches multiple unauthorized tool calls."""
        response = ModelResponse(
            text="I'll delete and execute.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_1", "name": "delete_file", "arguments": {"path": "/data/file.txt"}},
                {"id": "call_2", "name": "execute_code", "arguments": {"code": "rm -rf /"}},
            ],
        )
        test_case = TestCase(
            id="test_multiple_unauthorized",
            prompt="Delete and execute",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) == 2
        assert result.violations[0].rule_id == "tool_policy_delete_file"
        assert result.violations[1].rule_id == "tool_policy_execute_code"
        assert result.metadata["violations_count"] == 2

    def test_mixed_authorized_unauthorized(self, detector: ToolPolicyDetector) -> None:
        """Test detector catches violations when mixing authorized and unauthorized tools."""
        response = ModelResponse(
            text="I'll search and then delete.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_1", "name": "search", "arguments": {"query": "test"}},
                {"id": "call_2", "name": "delete_file", "arguments": {"path": "/data/file.txt"}},
            ],
        )
        test_case = TestCase(
            id="test_mixed",
            prompt="Search and delete",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "tool_policy_delete_file"
        assert result.metadata["tool_calls_found"] == 2
        assert result.metadata["violations_count"] == 1

    def test_unknown_tool_name(self, detector: ToolPolicyDetector) -> None:
        """Test detector handles tool calls with missing name field."""
        response = ModelResponse(
            text="Tool call without name.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_1", "arguments": {"param": "value"}},
            ],
        )
        test_case = TestCase(
            id="test_unknown_name",
            prompt="Call tool",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "tool_policy_unknown"
        assert result.violations[0].matched_text == "unknown"

    def test_violation_includes_tool_id(self, detector: ToolPolicyDetector) -> None:
        """Test that violations include tool call ID."""
        response = ModelResponse(
            text="Unauthorized call.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_abc123", "name": "delete_file", "arguments": {}},
            ],
        )
        test_case = TestCase(
            id="test_tool_id",
            prompt="Delete file",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "tool_policy_delete_file"

    def test_metadata_includes_allowed_tools(self, detector: ToolPolicyDetector) -> None:
        """Test that metadata includes allowed tools."""
        response = ModelResponse(
            text="Test response",
            meta={"model": "test"},
        )
        test_case = TestCase(
            id="test_metadata",
            prompt="Test prompt",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert "allowed_tools" in result.metadata
        assert "search" in result.metadata["allowed_tools"]
        assert "calculator" in result.metadata["allowed_tools"]
        assert "read_file" in result.metadata["allowed_tools"]

    def test_all_tools_authorized_passes(self, detector: ToolPolicyDetector) -> None:
        """Test that all authorized tools pass validation."""
        response = ModelResponse(
            text="Using all allowed tools.",
            meta={"model": "test"},
            tool_calls=[
                {"id": "call_1", "name": "search", "arguments": {}},
                {"id": "call_2", "name": "calculator", "arguments": {}},
                {"id": "call_3", "name": "read_file", "arguments": {}},
            ],
        )
        test_case = TestCase(
            id="test_all_authorized",
            prompt="Use all tools",
            metadata={"category": "utility"},
        )

        result = detector.check(response, test_case)

        assert result.passed is True
        assert len(result.violations) == 0
        assert result.metadata["tool_calls_found"] == 3
        assert result.metadata["violations_count"] == 0
