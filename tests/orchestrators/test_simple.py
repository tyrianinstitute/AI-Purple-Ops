"""Unit tests for SimpleOrchestrator."""

import pytest

from aipop.adapters.mock import MockAdapter
from aipop.core.models import TestCase
from aipop.core.orchestrator_config import OrchestratorConfig
from aipop.orchestrators.simple import SimpleOrchestrator


def test_simple_orchestrator_basic():
    """Test simple orchestrator passes prompt to adapter."""
    orchestrator = SimpleOrchestrator()
    adapter = MockAdapter(seed=42)
    test_case = TestCase(id="test1", prompt="Hello", metadata={})

    response = orchestrator.execute_prompt("Hello", test_case, adapter)

    assert response.text is not None
    assert isinstance(response.text, str)
    assert response.meta["orchestrator"] == "simple"


def test_simple_orchestrator_with_config():
    """Test orchestrator respects instance config."""
    config = OrchestratorConfig(debug=True, verbose=True)
    orchestrator = SimpleOrchestrator(config=config)

    assert orchestrator.config.debug is True
    assert orchestrator.config.verbose is True


def test_simple_orchestrator_test_metadata_override():
    """Test per-test metadata config override."""
    config = OrchestratorConfig(debug=False)
    orchestrator = SimpleOrchestrator(config=config)
    adapter = MockAdapter(seed=42)

    test_case = TestCase(
        id="test1",
        prompt="Hello",
        metadata={
            "orchestrator_config": {
                "debug": True,  # Override instance config
                "verbose": True,
            }
        },
    )

    response = orchestrator.execute_prompt("Hello", test_case, adapter)
    # Debug mode should be enabled (from test metadata)
    assert len(orchestrator._execution_history) > 0


def test_simple_orchestrator_config_override():
    """Test per-call config override."""
    orchestrator = SimpleOrchestrator()
    adapter = MockAdapter(seed=42)
    test_case = TestCase(id="test1", prompt="Hello", metadata={})

    response = orchestrator.execute_prompt(
        "Hello",
        test_case,
        adapter,
        config_override={"debug": True},
    )

    assert len(orchestrator._execution_history) > 0


def test_simple_orchestrator_config_hierarchy():
    """Test configuration hierarchy: test metadata > override > instance > defaults."""
    instance_config = OrchestratorConfig(debug=False, verbose=False)
    orchestrator = SimpleOrchestrator(config=instance_config)
    adapter = MockAdapter(seed=42)

    # Test metadata should override instance config
    test_case = TestCase(
        id="test1",
        prompt="Hello",
        metadata={"orchestrator_config": {"debug": True}},
    )

    response = orchestrator.execute_prompt("Hello", test_case, adapter)
    # Debug should be True (from test metadata, overriding instance False)
    assert len(orchestrator._execution_history) > 0


def test_simple_orchestrator_reset():
    """Test reset_state clears state."""
    orchestrator = SimpleOrchestrator()
    orchestrator._state["test"] = "value"
    orchestrator.reset_state()
    assert len(orchestrator._state) == 0


def test_simple_orchestrator_debug_info():
    """Test get_debug_info returns comprehensive state."""
    config = OrchestratorConfig(debug=True)
    orchestrator = SimpleOrchestrator(config=config)
    adapter = MockAdapter(seed=42)
    test_case = TestCase(id="test1", prompt="Hello", metadata={})

    orchestrator.execute_prompt("Hello", test_case, adapter)
    debug_info = orchestrator.get_debug_info()

    assert debug_info["orchestrator_type"] == "simple"
    assert "config" in debug_info
    assert "state" in debug_info
    assert "execution_history" in debug_info
    assert debug_info["total_executions"] == 1


def test_simple_orchestrator_verbose_logging():
    """Test verbose mode logs execution details."""
    config = OrchestratorConfig(verbose=True)
    orchestrator = SimpleOrchestrator(config=config)
    adapter = MockAdapter(seed=42)
    test_case = TestCase(id="test1", prompt="Hello", metadata={})

    orchestrator.execute_prompt("Hello", test_case, adapter)

    assert len(orchestrator._execution_history) > 0
    assert any("execute_prompt" in entry["event"] for entry in orchestrator._execution_history)


def test_simple_orchestrator_error_logging():
    """Test errors are logged in debug mode."""
    config = OrchestratorConfig(debug=True)
    orchestrator = SimpleOrchestrator(config=config)

    # Create adapter that will raise error
    class ErrorAdapter:
        def invoke(self, prompt: str) -> str:
            raise ValueError("Test error")

    test_case = TestCase(id="test1", prompt="Hello", metadata={})

    with pytest.raises(ValueError):
        orchestrator.execute_prompt("Hello", test_case, ErrorAdapter())

    # Error should be logged
    assert any("error" in entry["event"] for entry in orchestrator._execution_history)


def test_simple_orchestrator_metadata_in_response():
    """Test response includes orchestrator metadata."""
    orchestrator = SimpleOrchestrator()
    adapter = MockAdapter(seed=42)
    test_case = TestCase(id="test1", prompt="Hello", metadata={})

    response = orchestrator.execute_prompt("Hello", test_case, adapter)

    assert "orchestrator" in response.meta
    assert "config_used" in response.meta
    assert response.meta["orchestrator"] == "simple"
