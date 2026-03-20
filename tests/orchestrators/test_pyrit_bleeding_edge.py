"""Tests for PyRIT bleeding-edge feature compatibility."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from aipop.core.models import ModelResponse, TestCase
from aipop.core.orchestrator_config import OrchestratorConfig
from aipop.orchestrators.pyrit import PyRITOrchestrator


@pytest.fixture
def pyrit_config(tmp_path: Path):
    """Create PyRIT config with temporary DuckDB path."""
    return OrchestratorConfig(
        orchestrator_type="pyrit",
        debug=False,
        custom_params={
            "max_turns": 5,
            "db_path": str(tmp_path / "test_conversations.duckdb"),
            "context_window": 3,
        },
    )


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


def test_get_raw_memory_escape_hatch(pyrit_config):
    """Test get_raw_memory() escape hatch for bleeding-edge features."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Get raw PyRIT memory
    raw_memory = orchestrator.get_raw_memory()

    # Verify it's the actual DuckDB memory object
    assert raw_memory is not None
    assert raw_memory == orchestrator.memory

    # Verify we can call PyRIT methods directly
    from pyrit.memory import DuckDBMemory

    assert isinstance(raw_memory, DuckDBMemory)


def test_getattr_passthrough_for_memory_methods(pyrit_config):
    """Test __getattr__ passthrough for PyRIT memory methods."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Test that PyRIT memory methods are accessible via passthrough
    # get_prompt_request_pieces is a real PyRIT memory method
    assert hasattr(orchestrator, "get_prompt_request_pieces")

    # Should be callable
    method = orchestrator.get_prompt_request_pieces
    assert callable(method)


def test_getattr_raises_for_nonexistent_attributes(pyrit_config):
    """Test __getattr__ raises AttributeError for non-existent attributes."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Try to access non-existent attribute
    with pytest.raises(AttributeError, match="object has no attribute 'totally_fake_method'"):
        orchestrator.totally_fake_method


def test_getattr_doesnt_break_existing_methods(pyrit_config, mock_adapter, test_case):
    """Test __getattr__ doesn't interfere with existing PyRITOrchestrator methods."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Existing methods should still work normally
    response = orchestrator.execute_prompt("Test", test_case, mock_adapter)
    assert response.text == "Mock response"

    history = orchestrator.get_conversation_history()
    assert len(history) == 1

    debug_info = orchestrator.get_debug_info()
    assert debug_info["orchestrator_type"] == "pyrit"


def test_bleeding_edge_feature_simulation(pyrit_config):
    """Simulate using a hypothetical new PyRIT feature via escape hatch."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Get raw memory for bleeding-edge feature access
    raw_memory = orchestrator.get_raw_memory()

    # Simulate new PyRIT feature (just call an existing method as proxy)
    # In real world, this would be a brand new PyRIT method
    conversation_id = "test-conversation-123"

    # This works because we have direct access to PyRIT internals
    entries = raw_memory.get_prompt_request_pieces(conversation_id=conversation_id)

    # Should return empty list for new conversation
    assert isinstance(entries, list)


def test_memory_none_handling_via_mock(pyrit_config, monkeypatch):
    """Test graceful handling when memory initialization fails."""

    # Mock DuckDBMemory to raise exception during init
    def mock_duckdb_init(*args, **kwargs):
        raise Exception("Simulated DuckDB failure")

    monkeypatch.setattr("aipop.orchestrators.pyrit.DuckDBMemory", mock_duckdb_init)

    # This should handle the exception gracefully
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Memory should be None (fallback)
    assert orchestrator.memory is None

    # get_raw_memory should return None
    assert orchestrator.get_raw_memory() is None

    # __getattr__ should raise meaningful error when memory is None
    with pytest.raises(AttributeError, match="Not found in PyRIT memory either"):
        orchestrator.some_pyrit_method()


def test_docstring_examples_work(pyrit_config):
    """Test that examples from docstrings actually work."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Example from get_raw_memory() docstring
    raw_memory = orchestrator.get_raw_memory()
    assert raw_memory is not None

    # Example would use new PyRIT feature
    # We'll just verify we can access PyRIT methods
    from pyrit.memory import DuckDBMemory

    assert isinstance(raw_memory, DuckDBMemory)


def test_private_attributes_not_forwarded(pyrit_config):
    """Test that private attributes (_xxx) are not forwarded to PyRIT memory."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Private attributes should raise AttributeError, not forward
    with pytest.raises(AttributeError):
        orchestrator._nonexistent_private_attr


def test_callable_vs_noncallable_passthrough(pyrit_config):
    """Test that __getattr__ handles both callable and non-callable attributes."""
    orchestrator = PyRITOrchestrator(config=pyrit_config)

    # Test callable (method)
    method = orchestrator.get_prompt_request_pieces
    assert callable(method)

    # Test non-callable (attribute)
    # DuckDB memory has db_path attribute
    raw_memory = orchestrator.get_raw_memory()
    if hasattr(raw_memory, "db_path"):
        # Access via passthrough
        db_path = orchestrator.db_path
        assert db_path is not None
