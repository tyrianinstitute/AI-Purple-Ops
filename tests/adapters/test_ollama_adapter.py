"""Tests for Ollama adapter."""

from __future__ import annotations

import pytest

from aipop.adapters.ollama import OllamaAdapter


class TestOllamaAdapter:
    """Test Ollama adapter (requires Ollama to be running)."""

    def test_ollama_adapter_no_connection(self) -> None:
        """Test Ollama adapter raises error when Ollama not running."""
        # This should fail if Ollama is not running
        with pytest.raises(RuntimeError, match="Ollama not running"):
            OllamaAdapter(model="tinyllama", base_url="http://localhost:99999")

    @pytest.mark.skipif(True, reason="Requires Ollama to be running with tinyllama model")
    def test_ollama_adapter_with_connection(self) -> None:
        """Test Ollama adapter when Ollama is available."""
        # This test only runs if Ollama is available
        adapter = OllamaAdapter(model="tinyllama")
        response = adapter.invoke("Say hello")
        assert response.text is not None
        assert response.meta["cost_usd"] == 0.0  # Local model is free
        assert "model" in response.meta
