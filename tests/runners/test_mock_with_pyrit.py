"""Integration tests for MockRunner with PyRIT orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from aipop.core.models import ModelResponse, TestCase
from aipop.core.orchestrator_config import OrchestratorConfig
from aipop.orchestrators.pyrit import PyRITOrchestrator
from aipop.runners.mock import MockRunner


@pytest.fixture
def mock_adapter():
    """Create mock adapter for testing."""
    adapter = Mock()
    adapter.invoke.return_value = ModelResponse(
        text="Mock response", meta={"model": "mock"}, tool_calls=[]
    )
    return adapter


@pytest.fixture
def test_case():
    """Create test case for testing."""
    return TestCase(id="test-1", prompt="Test prompt", metadata={"suite_id": "test-suite"})


@pytest.fixture
def pyrit_orchestrator(tmp_path: Path):
    """Create PyRIT orchestrator with test config."""
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        custom_params={
            "max_turns": 3,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "context_window": 2,
        },
    )
    return PyRITOrchestrator(config=config)


def test_runner_without_orchestrator(mock_adapter, test_case):
    """Test MockRunner without orchestrator (baseline)."""
    runner = MockRunner(adapter=mock_adapter, seed=42)

    result = runner.execute(test_case)

    assert result.test_id == "test-1"
    assert result.response == "Mock response"
    assert result.passed is True
    assert "multi_turn" not in result.metadata


def test_runner_with_pyrit_single_turn(mock_adapter, test_case, pyrit_orchestrator):
    """Test MockRunner with PyRIT orchestrator in single-turn mode."""
    # Override max_turns to 1 for single-turn
    pyrit_orchestrator.max_turns = 1

    runner = MockRunner(adapter=mock_adapter, seed=42, orchestrator=pyrit_orchestrator)

    result = runner.execute(test_case)

    assert result.test_id == "test-1"
    assert result.response == "Mock response"
    assert result.passed is True
    assert result.metadata["model_meta"]["orchestrator"] == "pyrit"
    assert result.metadata["model_meta"]["turn"] == 1


def test_runner_with_pyrit_multi_turn(mock_adapter, test_case, pyrit_orchestrator):
    """Test MockRunner with PyRIT orchestrator in multi-turn mode."""
    runner = MockRunner(adapter=mock_adapter, seed=42, orchestrator=pyrit_orchestrator)

    result = runner.execute(test_case)

    assert result.test_id == "test-1"
    assert result.passed is True
    assert result.metadata["multi_turn"] is True
    assert result.metadata["total_turns"] == 3
    assert len(result.metadata["turn_results"]) == 3

    # Verify each turn
    for i, turn_result in enumerate(result.metadata["turn_results"], 1):
        assert turn_result["turn"] == i
        assert turn_result["response"] == "Mock response"


def test_runner_multi_turn_aggregation(mock_adapter, test_case, pyrit_orchestrator):
    """Test that runner aggregates results across multiple turns."""
    # Setup adapter to return different responses per turn
    responses = [
        ModelResponse(text=f"Response {i}", meta={"model": "mock"}, tool_calls=[])
        for i in range(1, 4)
    ]
    mock_adapter.invoke.side_effect = responses

    runner = MockRunner(adapter=mock_adapter, seed=42, orchestrator=pyrit_orchestrator)

    result = runner.execute(test_case)

    # Final response should be from last turn
    assert result.response == "Response 3"
    assert result.metadata["total_turns"] == 3

    # Verify all turns are recorded
    for i in range(1, 4):
        turn_result = result.metadata["turn_results"][i - 1]
        assert turn_result["response"] == f"Response {i}"


def test_runner_orchestrator_state_reset(mock_adapter, pyrit_orchestrator, tmp_path):
    """Test that orchestrator state is reset between test cases."""
    runner = MockRunner(adapter=mock_adapter, seed=42, orchestrator=pyrit_orchestrator)

    # Execute first test case
    test_case1 = TestCase(id="test-1", prompt="Test 1", metadata={})
    result1 = runner.execute(test_case1)
    assert result1.metadata["total_turns"] == 3

    # Execute second test case - orchestrator should be reset
    test_case2 = TestCase(id="test-2", prompt="Test 2", metadata={})
    result2 = runner.execute(test_case2)
    assert result2.metadata["total_turns"] == 3

    # Verify orchestrator was reset (conversation ID changed)
    assert (
        result1.metadata["model_meta"]["conversation_id"]
        != result2.metadata["model_meta"]["conversation_id"]
    )


def test_runner_per_test_config_override(mock_adapter, test_case, tmp_path):
    """Test per-test configuration override."""
    # Create orchestrator with default config
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        debug=False,
        custom_params={
            "max_turns": 3,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
        },
    )
    orchestrator = PyRITOrchestrator(config=config)

    runner = MockRunner(adapter=mock_adapter, seed=42, orchestrator=orchestrator)

    # Test case with metadata override
    test_case_with_override = TestCase(
        id="test-override",
        prompt="Test prompt",
        metadata={"orchestrator_config": {"debug": True, "verbose": True}},
    )

    result = runner.execute(test_case_with_override)

    # Config should be overridden
    assert result.metadata["model_meta"]["config_used"]["debug"] is True
    assert result.metadata["model_meta"]["config_used"]["verbose"] is True


def test_runner_execute_many_with_pyrit(mock_adapter, pyrit_orchestrator):
    """Test execute_many with PyRIT orchestrator."""
    runner = MockRunner(adapter=mock_adapter, seed=42, orchestrator=pyrit_orchestrator)

    test_cases = [
        TestCase(id="test-1", prompt="Test 1", metadata={}),
        TestCase(id="test-2", prompt="Test 2", metadata={}),
        TestCase(id="test-3", prompt="Test 3", metadata={}),
    ]

    results = list(runner.execute_many(test_cases))

    assert len(results) == 3
    assert all(r.metadata["multi_turn"] is True for r in results)
    assert all(r.metadata["total_turns"] == 3 for r in results)

    # Verify each test has unique conversation ID
    conversation_ids = [r.metadata["model_meta"]["conversation_id"] for r in results]
    assert len(set(conversation_ids)) == 3  # All unique


def test_runner_transcript_saving_with_pyrit(mock_adapter, pyrit_orchestrator, tmp_path):
    """Test transcript saving with multi-turn conversations."""
    transcripts_dir = tmp_path / "transcripts"

    runner = MockRunner(
        adapter=mock_adapter,
        seed=42,
        orchestrator=pyrit_orchestrator,
        transcripts_dir=transcripts_dir,
    )

    test_case = TestCase(id="test-1", prompt="Test prompt", metadata={})

    result = runner.execute(test_case)

    # Verify transcript was saved
    transcript_files = list(transcripts_dir.glob("test-1_*.json"))
    assert len(transcript_files) == 1

    # Verify transcript contains multi-turn information
    import json

    with open(transcript_files[0]) as f:
        transcript = json.load(f)

    assert "multi_turn" in transcript["metadata"]
    assert transcript["metadata"]["multi_turn"] is True
    assert "turn_results" in transcript["metadata"]


def test_runner_detector_integration_multi_turn(mock_adapter, pyrit_orchestrator):
    """Test detector integration with multi-turn execution."""
    # Create mock detector
    mock_detector = Mock()
    from aipop.core.detectors import DetectorResult

    mock_detector.check.return_value = DetectorResult(
        detector_name="mock_detector", passed=True, violations=[], metadata={}
    )

    runner = MockRunner(
        adapter=mock_adapter, seed=42, orchestrator=pyrit_orchestrator, detectors=[mock_detector]
    )

    test_case = TestCase(id="test-1", prompt="Test prompt", metadata={})

    result = runner.execute(test_case)

    # Detector should be called for each turn (3 times)
    assert mock_detector.check.call_count == 3
    assert len(result.detector_results) == 3


def test_runner_error_handling_with_pyrit(pyrit_orchestrator):
    """Test error handling with failing adapter."""
    failing_adapter = Mock()
    failing_adapter.invoke.side_effect = Exception("Adapter failed")

    runner = MockRunner(adapter=failing_adapter, seed=42, orchestrator=pyrit_orchestrator)

    test_case = TestCase(id="test-1", prompt="Test prompt", metadata={})

    result = runner.execute(test_case)

    # Should return failed result instead of crashing
    assert result.passed is False
    assert "error" in result.metadata
    assert "Adapter failed" in result.metadata["error"]
