"""Tests for PyRIT orchestrator with multi-turn conversation support."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

pytestmark = pytest.mark.skipif(
    not importlib.util.find_spec("pyrit"),
    reason="pyrit not installed",
)

from aipop.core.models import ModelResponse, TestCase
from aipop.core.orchestrator_config import OrchestratorConfig
from aipop.orchestrators.pyrit import PyRITOrchestrator


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
def pyrit_config(tmp_path: Path):
    """Create PyRIT config with temporary DuckDB path."""
    return OrchestratorConfig(
        orchestrator_type="pyrit",
        debug=False,
        verbose=False,
        custom_params={
            "max_turns": 5,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "context_window": 3,
            "enable_branching": True,
            "persist_history": True,
            "strategy": "multi_turn",
            "state_tracking": True,
        },
    )


def test_pyrit_orchestrator_basic_init(pyrit_config):
    """Test basic PyRIT orchestrator initialization."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    assert orchestrator.max_turns == 5
    assert orchestrator.context_window == 3
    assert orchestrator.enable_branching is True
    assert orchestrator.persist_history is True


def test_pyrit_orchestrator_single_turn(pyrit_config, mock_adapter, test_case):
    """Test single-turn execution (basic functionality)."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    response = orchestrator.execute_prompt("Test prompt", test_case, mock_adapter)

    assert response.text == "Mock response"
    assert response.meta["orchestrator"] == "pyrit"
    assert response.meta["turn"] == 1
    assert response.meta["max_turns"] == 5
    mock_adapter.invoke.assert_called_once_with("Test prompt")


def test_pyrit_orchestrator_multi_turn_conversation(pyrit_config, mock_adapter, test_case):
    """Test multi-turn conversation state tracking."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Turn 1
    response1 = orchestrator.execute_prompt("Turn 1", test_case, mock_adapter)
    assert response1.meta["turn"] == 1
    assert len(orchestrator._conversation_history) == 1

    # Turn 2
    response2 = orchestrator.execute_prompt("Turn 2", test_case, mock_adapter)
    assert response2.meta["turn"] == 2
    assert len(orchestrator._conversation_history) == 2

    # Turn 3
    response3 = orchestrator.execute_prompt("Turn 3", test_case, mock_adapter)
    assert response3.meta["turn"] == 3
    assert len(orchestrator._conversation_history) == 3


def test_pyrit_orchestrator_conversation_reset(pyrit_config, mock_adapter, test_case):
    """Test conversation reset functionality."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Execute some turns
    orchestrator.execute_prompt("Turn 1", test_case, mock_adapter)
    orchestrator.execute_prompt("Turn 2", test_case, mock_adapter)
    assert len(orchestrator._conversation_history) == 2
    assert orchestrator._turn_counter == 2

    # Reset conversation
    orchestrator.reset_conversation()
    assert len(orchestrator._conversation_history) == 0
    assert orchestrator._turn_counter == 0
    assert orchestrator._current_conversation_id is None


def test_pyrit_orchestrator_context_building(pyrit_config, mock_adapter, test_case):
    """Test conversation context building from history."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Execute multiple turns
    for i in range(1, 6):
        orchestrator.execute_prompt(f"Turn {i}", test_case, mock_adapter)

    # Build context (should include last 3 turns based on context_window=3)
    context = orchestrator._build_context()

    assert "Turn 3" in context
    assert "Turn 4" in context
    assert "Turn 5" in context
    assert "Turn 1" not in context  # Outside context window
    assert "Turn 2" not in context  # Outside context window


def test_pyrit_orchestrator_config_hierarchy(pyrit_config, mock_adapter, test_case):
    """Test configuration hierarchy (test metadata > instance config)."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Test with metadata override
    test_case_with_override = TestCase(
        id="test-override",
        prompt="Test prompt",
        metadata={"orchestrator_config": {"debug": True, "verbose": True}},
    )

    response = orchestrator.execute_prompt("Test prompt", test_case_with_override, mock_adapter)

    # Config should be overridden
    assert response.meta["config_used"]["debug"] is True
    assert response.meta["config_used"]["verbose"] is True


def test_pyrit_orchestrator_debug_mode(mock_adapter, test_case, tmp_path):
    """Test debug mode with execution history."""
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        debug=True,
        custom_params={
            "max_turns": 3,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "context_window": 2,
        },
    )
    orchestrator = PyRITOrchestrator(config=config)

    response = orchestrator.execute_prompt("Test", test_case, mock_adapter)

    assert response.meta["orchestrator"] == "pyrit"
    assert "conversation_history" in response.meta
    assert "execution_history" in response.meta
    assert len(orchestrator._execution_history) > 0


def test_pyrit_orchestrator_verbose_mode(mock_adapter, test_case, tmp_path, capsys):
    """Test verbose mode with console logging."""
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        verbose=True,
        custom_params={
            "max_turns": 2,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
        },
    )
    orchestrator = PyRITOrchestrator(config=config)

    orchestrator.execute_prompt("Test", test_case, mock_adapter)

    captured = capsys.readouterr()
    assert "[PyRIT Orchestrator]" in captured.out or "Started new conversation" in captured.out


def test_pyrit_orchestrator_conversation_history_retrieval(pyrit_config, mock_adapter, test_case):
    """Test conversation history retrieval."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Execute turns
    orchestrator.execute_prompt("Turn 1", test_case, mock_adapter)
    orchestrator.execute_prompt("Turn 2", test_case, mock_adapter)

    # Get history
    history = orchestrator.get_conversation_history()

    assert len(history) == 2
    assert history[0]["turn"] == 1
    assert history[0]["prompt"] == "Turn 1"
    assert history[1]["turn"] == 2
    assert history[1]["prompt"] == "Turn 2"


def test_pyrit_orchestrator_reset_state(pyrit_config, mock_adapter, test_case):
    """Test full state reset between test cases."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Execute turns
    orchestrator.execute_prompt("Turn 1", test_case, mock_adapter)
    orchestrator.execute_prompt("Turn 2", test_case, mock_adapter)

    # Reset state
    orchestrator.reset_state()

    assert len(orchestrator._conversation_history) == 0
    assert orchestrator._turn_counter == 0
    assert orchestrator._current_conversation_id is None
    assert len(orchestrator._state) == 0


def test_pyrit_orchestrator_debug_info(pyrit_config, mock_adapter, test_case):
    """Test get_debug_info method."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    orchestrator.execute_prompt("Test", test_case, mock_adapter)

    debug_info = orchestrator.get_debug_info()

    assert debug_info["orchestrator_type"] == "pyrit"
    assert "conversation_id" in debug_info
    assert debug_info["turn_counter"] == 1
    assert "conversation_history" in debug_info
    assert debug_info["max_turns"] == 5
    assert debug_info["context_window"] == 3


def test_pyrit_orchestrator_conversation_branching(mock_adapter, test_case, tmp_path):
    """Test conversation branching functionality."""
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        custom_params={
            "max_turns": 5,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "enable_branching": True,
        },
    )
    orchestrator = PyRITOrchestrator(config=config)

    # Create conversation with multiple turns
    for i in range(1, 4):
        orchestrator.execute_prompt(f"Turn {i}", test_case, mock_adapter)

    original_conversation_id = orchestrator._current_conversation_id

    # Branch at turn 2
    orchestrator.branch_conversation(turn_id=2)

    # Verify branching
    assert orchestrator._current_conversation_id != original_conversation_id
    assert orchestrator._turn_counter == 2
    assert len(orchestrator._conversation_history) == 2


def test_pyrit_orchestrator_branching_disabled(mock_adapter, test_case, tmp_path):
    """Test that branching raises error when disabled."""
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        custom_params={
            "max_turns": 5,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "enable_branching": False,  # Disabled
        },
    )
    orchestrator = PyRITOrchestrator(config=config)

    orchestrator.execute_prompt("Turn 1", test_case, mock_adapter)

    with pytest.raises(ValueError, match="branching is disabled"):
        orchestrator.branch_conversation(turn_id=1)


def test_pyrit_orchestrator_mutation_integration(mock_adapter, test_case, tmp_path):
    """Test integration with mutation engine."""
    config = OrchestratorConfig(
        orchestrator_type="pyrit",
        custom_params={
            "max_turns": 2,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "enable_mutations": True,
            "mutation_config": "configs/mutation/default.yaml",
        },
    )

    with patch("aipop.mutators.mutation_engine.MutationEngine") as mock_mutation_engine_class:
        mock_engine = Mock()
        mock_engine.mutate_with_feedback.return_value = []  # No mutations
        mock_mutation_engine_class.return_value = mock_engine

        orchestrator = PyRITOrchestrator(config=config)

        # Execute with mutations enabled
        orchestrator.execute_prompt("Test", test_case, mock_adapter)

        # Verify mutation engine was called
        assert orchestrator.mutation_engine is not None


def test_pyrit_orchestrator_error_handling(pyrit_config, test_case):
    """Test error handling with failing adapter."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Create failing adapter
    failing_adapter = Mock()
    failing_adapter.invoke.side_effect = Exception("Adapter failed")

    with pytest.raises(Exception, match="Adapter failed"):
        orchestrator.execute_prompt("Test", test_case, failing_adapter)


def test_pyrit_orchestrator_default_config_fallback():
    """Test default config when no config provided."""
    orchestrator = PyRITOrchestrator()

    assert orchestrator.config.orchestrator_type == "simple"  # Default
    assert orchestrator.max_turns == 10  # Default from custom_params.get
    assert orchestrator.context_window == 5
