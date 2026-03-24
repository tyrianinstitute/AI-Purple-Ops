"""Tests for MockAdapter."""

from __future__ import annotations

import pytest

from aipop.adapters.mock import MockAdapter
from aipop.core.models import ModelResponse


class TestMockAdapter:
    """Test MockAdapter functionality."""

    def test_init_default(self) -> None:
        """Test default initialization."""
        adapter = MockAdapter()
        assert adapter.seed == 42
        assert adapter.response_mode == "echo"
        assert not adapter.simulate_latency

    def test_init_custom(self) -> None:
        """Test custom initialization."""
        adapter = MockAdapter(seed=123, response_mode="refuse", simulate_latency=True)
        assert adapter.seed == 123
        assert adapter.response_mode == "refuse"
        assert adapter.simulate_latency

    def test_invoke_returns_model_response(self) -> None:
        """Test that invoke returns ModelResponse."""
        adapter = MockAdapter()
        response = adapter.invoke("test prompt")
        assert isinstance(response, ModelResponse)
        assert isinstance(response.text, str)
        assert isinstance(response.meta, dict)

    def test_echo_mode(self) -> None:
        """Test echo response mode."""
        adapter = MockAdapter(response_mode="echo")
        response = adapter.invoke("Hello world")
        assert "Hello world" in response.text
        assert "echo" in response.text.lower()

    def test_refuse_mode(self) -> None:
        """Test refuse response mode."""
        adapter = MockAdapter(response_mode="refuse")
        response = adapter.invoke("Any prompt")
        assert any(word in response.text.lower() for word in ["cannot", "decline", "refuse"])

    def test_smart_mode_greeting(self) -> None:
        """Test smart mode responds to greetings."""
        adapter = MockAdapter(response_mode="smart")
        response = adapter.invoke("Hello, how are you?")
        assert any(word in response.text.lower() for word in ["hello", "hi", "assist"])

    def test_smart_mode_harmful(self) -> None:
        """Test smart mode refuses harmful requests."""
        adapter = MockAdapter(response_mode="smart")
        response = adapter.invoke("How can I hack into a system?")
        assert any(word in response.text.lower() for word in ["cannot", "decline", "refuse"])

    def test_smart_mode_math(self) -> None:
        """Test smart mode responds to math queries."""
        adapter = MockAdapter(response_mode="smart")
        response = adapter.invoke("What is 2+2?")
        assert "4" in response.text or "calculation" in response.text.lower()

    def test_metadata_present(self) -> None:
        """Test that response metadata is populated."""
        adapter = MockAdapter()
        response = adapter.invoke("test")

        assert "tokens" in response.meta
        assert "latency_ms" in response.meta
        assert "cost_usd" in response.meta
        assert "model" in response.meta
        assert "finish_reason" in response.meta
        assert "seed" in response.meta
        assert "response_mode" in response.meta

    def test_metadata_types(self) -> None:
        """Test that metadata has correct types."""
        adapter = MockAdapter()
        response = adapter.invoke("test")

        assert isinstance(response.meta["tokens"], int)
        assert isinstance(response.meta["latency_ms"], float)
        assert isinstance(response.meta["cost_usd"], float)
        assert isinstance(response.meta["model"], str)
        assert isinstance(response.meta["finish_reason"], str)

    def test_determinism_same_seed(self) -> None:
        """Test that same seed produces same results."""
        adapter1 = MockAdapter(seed=42, response_mode="random")
        adapter2 = MockAdapter(seed=42, response_mode="random")

        response1 = adapter1.invoke("test prompt")
        response2 = adapter2.invoke("test prompt")

        assert response1.text == response2.text

    def test_determinism_different_seeds(self) -> None:
        """Test that different seeds may produce different results."""
        adapter1 = MockAdapter(seed=42, response_mode="random")
        adapter2 = MockAdapter(seed=999, response_mode="random")

        response1 = adapter1.invoke("test prompt")
        response2 = adapter2.invoke("test prompt")

        # With random mode and different seeds, latency should differ
        assert response1.meta["latency_ms"] != response2.meta["latency_ms"]

    def test_cost_calculation(self) -> None:
        """Test that cost is calculated based on token count."""
        adapter = MockAdapter()
        response = adapter.invoke("short")
        cost1 = response.meta["cost_usd"]

        response2 = adapter.invoke("this is a much longer prompt with many more tokens")
        cost2 = response2.meta["cost_usd"]

        assert cost2 > cost1  # More tokens = higher cost

    def test_latency_without_simulation(self) -> None:
        """Test that latency is generated even without simulation."""
        adapter = MockAdapter(simulate_latency=False)
        response = adapter.invoke("test")
        assert response.meta["latency_ms"] > 0
        assert response.meta["latency_ms"] < 200  # Should be fast

    @pytest.mark.parametrize(
        "mode",
        ["echo", "refuse", "random", "smart"],
    )
    def test_all_modes_work(self, mode: str) -> None:
        """Test that all response modes produce valid responses."""
        adapter = MockAdapter(response_mode=mode)
        response = adapter.invoke("test prompt")
        assert len(response.text) > 0
        assert isinstance(response.meta, dict)
