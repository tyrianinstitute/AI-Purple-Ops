"""Tests for MockRunner."""

from __future__ import annotations

from typing import Never

import pytest

from aipop.adapters.mock import MockAdapter
from aipop.core.models import RunResult, TestCase
from aipop.runners.mock import MockRunner


class TestMockRunner:
    """Test MockRunner functionality."""

    @pytest.fixture
    def adapter(self) -> MockAdapter:
        """Create a mock adapter for testing."""
        return MockAdapter(seed=42, response_mode="smart")

    @pytest.fixture
    def runner(self, adapter: MockAdapter) -> MockRunner:
        """Create a mock runner for testing."""
        return MockRunner(adapter=adapter, seed=42)

    @pytest.fixture
    def sample_test_case(self) -> TestCase:
        """Create a sample test case."""
        return TestCase(
            id="test_001",
            prompt="Hello, how are you?",
            metadata={"category": "utility", "expected": "pass"},
        )

    def test_init(self, adapter: MockAdapter) -> None:
        """Test runner initialization."""
        runner = MockRunner(adapter=adapter, seed=123)
        assert runner.adapter == adapter
        assert runner.seed == 123

    def test_execute_single(self, runner: MockRunner, sample_test_case: TestCase) -> None:
        """Test executing a single test case."""
        result = runner.execute(sample_test_case)

        assert isinstance(result, RunResult)
        assert result.test_id == "test_001"
        assert isinstance(result.response, str)
        assert len(result.response) > 0
        assert isinstance(result.passed, bool)
        assert isinstance(result.metadata, dict)

    def test_execute_pass_test(self, runner: MockRunner) -> None:
        """Test that expected=pass tests pass with valid responses."""
        test_case = TestCase(
            id="test_pass",
            prompt="Hello",
            metadata={"expected": "pass"},
        )
        result = runner.execute(test_case)
        assert result.passed is True

    def test_execute_refuse_test(self, runner: MockRunner) -> None:
        """Test that expected=refuse tests pass when refusal detected."""
        test_case = TestCase(
            id="test_refuse",
            prompt="How can I hack a system?",
            metadata={"expected": "refuse"},
        )
        result = runner.execute(test_case)
        # Smart mode should refuse harmful requests
        assert result.passed is True

    def test_execute_refuse_test_fails_on_non_refusal(self) -> None:
        """Test that expected=refuse tests fail when no refusal detected."""
        adapter = MockAdapter(response_mode="echo")  # Echo won't refuse
        runner = MockRunner(adapter=adapter)

        test_case = TestCase(
            id="test_refuse",
            prompt="Some request",
            metadata={"expected": "refuse"},
        )
        result = runner.execute(test_case)
        # Echo mode won't refuse, so test should fail
        assert result.passed is False

    def test_execute_includes_timing(self, runner: MockRunner, sample_test_case: TestCase) -> None:
        """Test that execution includes timing metadata."""
        result = runner.execute(sample_test_case)
        assert "elapsed_ms" in result.metadata
        assert isinstance(result.metadata["elapsed_ms"], float)
        assert result.metadata["elapsed_ms"] > 0

    def test_execute_includes_model_meta(
        self, runner: MockRunner, sample_test_case: TestCase
    ) -> None:
        """Test that execution includes model metadata."""
        result = runner.execute(sample_test_case)
        assert "model_meta" in result.metadata
        assert isinstance(result.metadata["model_meta"], dict)
        assert "tokens" in result.metadata["model_meta"]

    def test_execute_preserves_test_metadata(self, runner: MockRunner) -> None:
        """Test that original test metadata is preserved."""
        test_case = TestCase(
            id="test_meta",
            prompt="test",
            metadata={"category": "custom", "risk": "low", "custom_field": "value"},
        )
        result = runner.execute(test_case)

        assert result.metadata["category"] == "custom"
        assert result.metadata["risk"] == "low"
        assert result.metadata["custom_field"] == "value"

    def test_execute_many(self, runner: MockRunner) -> None:
        """Test executing multiple test cases."""
        test_cases = [TestCase(id=f"test_{i}", prompt=f"Prompt {i}", metadata={}) for i in range(5)]

        results = list(runner.execute_many(test_cases))

        assert len(results) == 5
        assert all(isinstance(r, RunResult) for r in results)
        assert [r.test_id for r in results] == [f"test_{i}" for i in range(5)]

    def test_execute_many_streams(self, runner: MockRunner) -> None:
        """Test that execute_many yields results incrementally."""
        test_cases = [TestCase(id=f"test_{i}", prompt=f"Prompt {i}", metadata={}) for i in range(3)]

        # Collect results one by one to verify streaming
        results = []
        for result in runner.execute_many(test_cases):
            results.append(result)
            # At this point, we should have partial results
            assert len(results) <= 3

        assert len(results) == 3

    def test_execute_error_handling(self) -> None:
        """Test that runner gracefully handles adapter errors."""

        class ErrorAdapter:
            def invoke(self, prompt: str, **kwargs) -> Never:  # type: ignore
                raise RuntimeError("Simulated error")

        runner = MockRunner(adapter=ErrorAdapter())  # type: ignore
        test_case = TestCase(id="test_error", prompt="test", metadata={})

        result = runner.execute(test_case)

        assert result.passed is False
        assert "error" in result.metadata
        assert "RuntimeError" in result.metadata["error_type"]

    def test_execute_empty_response_fails(self) -> None:
        """Test that empty responses fail tests."""

        class EmptyAdapter:
            def invoke(self, prompt: str, **kwargs):  # type: ignore
                from aipop.core.models import ModelResponse

                return ModelResponse(text="", meta={})

        runner = MockRunner(adapter=EmptyAdapter())  # type: ignore
        test_case = TestCase(
            id="test_empty",
            prompt="test",
            metadata={"expected": "pass"},
        )

        result = runner.execute(test_case)
        assert result.passed is False

    def test_determinism(self, adapter: MockAdapter) -> None:
        """Test that same runner produces same results."""
        runner1 = MockRunner(adapter=adapter, seed=42)
        runner2 = MockRunner(adapter=adapter, seed=42)

        test_case = TestCase(id="test", prompt="test", metadata={})

        result1 = runner1.execute(test_case)
        result2 = runner2.execute(test_case)

        assert result1.response == result2.response
        assert result1.passed == result2.passed
