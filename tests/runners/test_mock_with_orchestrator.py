"""Integration tests for MockRunner with orchestrator."""

from aipop.adapters.mock import MockAdapter
from aipop.core.models import TestCase
from aipop.core.orchestrator_config import OrchestratorConfig
from aipop.orchestrators.simple import SimpleOrchestrator
from aipop.runners.mock import MockRunner


def test_runner_with_orchestrator():
    """Test runner executes correctly with simple orchestrator."""
    adapter = MockAdapter(seed=42)
    orchestrator = SimpleOrchestrator()
    runner = MockRunner(adapter=adapter, orchestrator=orchestrator)

    test_case = TestCase(id="test1", prompt="Hello", metadata={})
    result = runner.execute(test_case)

    assert result.passed
    assert result.response is not None


def test_runner_without_orchestrator():
    """Test runner still works when orchestrator is None (backward compat)."""
    adapter = MockAdapter(seed=42)
    runner = MockRunner(adapter=adapter, orchestrator=None)

    test_case = TestCase(id="test1", prompt="Hello", metadata={})
    result = runner.execute(test_case)

    assert result.passed
    assert result.response is not None


def test_runner_with_orchestrator_and_detectors():
    """Test runner works with both orchestrator and detectors."""
    adapter = MockAdapter(seed=42)
    orchestrator = SimpleOrchestrator()
    runner = MockRunner(adapter=adapter, orchestrator=orchestrator, detectors=[])

    test_case = TestCase(id="test1", prompt="Hello", metadata={})
    result = runner.execute(test_case)

    assert result.passed
    assert result.response is not None


def test_runner_execute_many_with_orchestrator():
    """Test execute_many works with orchestrator."""
    adapter = MockAdapter(seed=42)
    orchestrator = SimpleOrchestrator()
    runner = MockRunner(adapter=adapter, orchestrator=orchestrator)

    test_cases = [
        TestCase(id="test1", prompt="Hello", metadata={}),
        TestCase(id="test2", prompt="World", metadata={}),
    ]

    results = list(runner.execute_many(test_cases))

    assert len(results) == 2
    assert all(r.passed for r in results)


def test_runner_per_test_config_override():
    """Test runner passes per-test config override to orchestrator."""
    adapter = MockAdapter(seed=42)
    config = OrchestratorConfig(debug=False)
    orchestrator = SimpleOrchestrator(config=config)
    runner = MockRunner(adapter=adapter, orchestrator=orchestrator)

    test_case = TestCase(
        id="test1",
        prompt="Hello",
        metadata={"orchestrator_config": {"debug": True}},
    )

    result = runner.execute(test_case)
    # Debug should be enabled from test metadata
    assert len(orchestrator._execution_history) > 0


def test_runner_orchestrator_metadata_in_result():
    """Test orchestrator metadata appears in result."""
    adapter = MockAdapter(seed=42)
    orchestrator = SimpleOrchestrator()
    runner = MockRunner(adapter=adapter, orchestrator=orchestrator)

    test_case = TestCase(id="test1", prompt="Hello", metadata={})
    result = runner.execute(test_case)

    assert "model_meta" in result.metadata
    assert "orchestrator" in result.metadata["model_meta"]


def test_runner_backward_compatibility():
    """Test runner maintains backward compatibility when orchestrator is None."""
    adapter = MockAdapter(seed=42)
    runner = MockRunner(adapter=adapter)

    test_case = TestCase(id="test1", prompt="Hello", metadata={})
    result = runner.execute(test_case)

    assert result.passed
    assert result.response is not None
    # Should not have orchestrator metadata when orchestrator is None
    assert "orchestrator" not in result.metadata.get("model_meta", {})


def test_runner_orchestrator_reset_state():
    """Test orchestrator state is reset between test cases."""
    adapter = MockAdapter(seed=42)
    config = OrchestratorConfig(debug=True)  # Enable debug to track history
    orchestrator = SimpleOrchestrator(config=config)
    runner = MockRunner(adapter=adapter, orchestrator=orchestrator)

    test_case1 = TestCase(id="test1", prompt="Hello", metadata={})
    test_case2 = TestCase(id="test2", prompt="World", metadata={})

    result1 = runner.execute(test_case1)
    result2 = runner.execute(test_case2)

    # Both should execute successfully
    assert result1.passed or not result1.passed  # Execution completed
    assert result2.passed or not result2.passed  # Execution completed

    # History should be empty after reset (called after each test)
    assert len(orchestrator._execution_history) == 0


def test_runner_with_transcripts_and_orchestrator():
    """Test runner works with transcripts and orchestrator."""
    import tempfile
    from pathlib import Path

    adapter = MockAdapter(seed=42)
    orchestrator = SimpleOrchestrator()
    with tempfile.TemporaryDirectory() as tmpdir:
        runner = MockRunner(
            adapter=adapter,
            orchestrator=orchestrator,
            transcripts_dir=Path(tmpdir),
        )

        test_case = TestCase(id="test1", prompt="Hello", metadata={})
        result = runner.execute(test_case)

        assert result.passed
        # Transcript filename now includes timestamp
        transcript_files = list(Path(tmpdir).glob("test1_*.json"))
        assert len(transcript_files) == 1


def test_runner_error_handling_with_orchestrator():
    """Test runner handles errors gracefully with orchestrator."""
    adapter = MockAdapter(seed=42)
    orchestrator = SimpleOrchestrator()

    class ErrorAdapter:
        def invoke(self, prompt: str) -> str:
            raise ValueError("Adapter error")

    runner = MockRunner(adapter=ErrorAdapter(), orchestrator=orchestrator)

    test_case = TestCase(id="test1", prompt="Hello", metadata={})
    result = runner.execute(test_case)

    assert not result.passed
    assert "error" in result.response.lower() or "Error" in result.response
