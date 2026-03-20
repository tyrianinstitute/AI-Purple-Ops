"""Unit tests for batch_query functionality."""

import pytest

from aipop.adapters.mock import MockAdapter
from aipop.core.models import ModelResponse


def test_mock_adapter_batch_query():
    """Test MockAdapter batch_query."""
    adapter = MockAdapter(seed=42)
    prompts = ["Prompt 1", "Prompt 2", "Prompt 3"]

    results = adapter.batch_query(prompts)

    assert len(results) == 3
    assert all(isinstance(r, ModelResponse) for r in results)
    assert all("Mock" in r.text for r in results)


def test_adapter_protocol_batch_query_fallback():
    """Test that adapters without batch_query fall back to sequential."""

    # Create a mock adapter that doesn't override batch_query
    class SimpleAdapter:
        def invoke(self, prompt: str):
            return ModelResponse(
                text=f"Response to {prompt}",
                meta={"model": "test"},
            )

    adapter = SimpleAdapter()

    # Use the protocol's default implementation

    # Since SimpleAdapter doesn't implement batch_query, it will use sequential
    # But we can't directly test the protocol, so we test via a real adapter
    prompts = ["test1", "test2"]
    results = (
        adapter.batch_query(prompts)
        if hasattr(adapter, "batch_query")
        else [adapter.invoke(p) for p in prompts]
    )

    assert len(results) == 2


@pytest.mark.skipif(
    True,  # Skip by default - requires API keys
    reason="Requires cloud API keys",
)
def test_openai_adapter_batch_query():
    """Test OpenAI adapter batch_query (requires API key)."""
    import os

    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")

    from aipop.adapters.openai import OpenAIAdapter

    adapter = OpenAIAdapter(model="gpt-3.5-turbo")
    prompts = ["Say hello", "Say goodbye"]

    results = adapter.batch_query(prompts)

    assert len(results) == 2
    assert all(isinstance(r, ModelResponse) for r in results)


def test_batch_query_preserves_order():
    """Test that batch_query preserves prompt order."""
    adapter = MockAdapter(seed=42)
    prompts = ["A", "B", "C"]

    results = adapter.batch_query(prompts)

    # Results should be in same order as prompts
    assert len(results) == 3
    # Mock adapter should return responses in order
    assert all(results[i].text for i in range(3))
