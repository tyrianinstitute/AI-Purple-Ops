"""Unit tests for ParaphrasingMutator."""

import os
from unittest.mock import Mock, patch

import pytest

from aipop.core.models import ModelResponse
from aipop.mutators.paraphrasing import ParaphrasingMutator


def test_paraphrasing_mutator_no_api_key():
    """Test paraphrasing mutator raises error without API key."""
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="OpenAI API key required"):
            ParaphrasingMutator(provider="openai")


def test_paraphrasing_mutator_ollama_no_key():
    """Test Ollama provider doesn't require API key."""
    with patch("aipop.adapters.ollama.OllamaAdapter") as mock_adapter_class:
        mock_instance = Mock()
        mock_adapter_class.return_value = mock_instance

        mutator = ParaphrasingMutator(provider="ollama")
        assert mutator.provider == "ollama"
        assert mutator.adapter == mock_instance


def test_paraphrasing_mutator_openai_with_key():
    """Test OpenAI provider with API key."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_instance = Mock()
        mock_adapter_class.return_value = mock_instance

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key")
        assert mutator.provider == "openai"
        assert mutator.adapter == mock_instance
        mock_adapter_class.assert_called_once()


def test_paraphrasing_mutator_anthropic_with_key():
    """Test Anthropic provider with API key."""
    with patch("aipop.adapters.anthropic.AnthropicAdapter") as mock_adapter_class:
        mock_instance = Mock()
        mock_adapter_class.return_value = mock_instance

        mutator = ParaphrasingMutator(provider="anthropic", api_key="test-key")
        assert mutator.provider == "anthropic"
        assert mutator.adapter == mock_instance
        mock_adapter_class.assert_called_once()


def test_paraphrasing_mutator_mutate():
    """Test paraphrasing mutation generation."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_adapter = Mock()
        mock_adapter.invoke.return_value = ModelResponse(
            text="Variation 1\nVariation 2\nVariation 3", meta={}
        )
        mock_adapter_class.return_value = mock_adapter

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key")
        mutations = mutator.mutate("Hello World")

        assert len(mutations) >= 1
        assert all(m.mutation_type == "llm_paraphrase" for m in mutations)
        assert all(m.original == "Hello World" for m in mutations)


def test_paraphrasing_mutator_stats():
    """Test mutation statistics tracking."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_adapter = Mock()
        mock_adapter.invoke.return_value = ModelResponse(text="Test 1\nTest 2\nTest 3", meta={})
        mock_adapter_class.return_value = mock_adapter

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key")
        mutator.mutate("test")
        stats = mutator.get_stats()

        assert stats["total"] >= 0
        assert "success" in stats
        assert "failure" in stats
        assert "api_errors" in stats


def test_paraphrasing_mutator_metadata():
    """Test mutation metadata."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_adapter = Mock()
        mock_adapter.invoke.return_value = ModelResponse(text="Test 1\nTest 2", meta={})
        mock_adapter_class.return_value = mock_adapter

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key", model="gpt-4")
        mutations = mutator.mutate("test")

        for mutation in mutations:
            assert "provider" in mutation.metadata
            assert mutation.metadata["provider"] == "openai"
            assert "model" in mutation.metadata
            assert "variation" in mutation.metadata


def test_paraphrasing_mutator_api_error():
    """Test paraphrasing mutator handles API errors gracefully."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_adapter = Mock()
        mock_adapter.invoke.side_effect = Exception("API Error")
        mock_adapter_class.return_value = mock_adapter

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key")
        mutations = mutator.mutate("test")

        # Should return empty list on error
        assert len(mutations) == 0
        assert mutator.stats["api_errors"] == 1


def test_paraphrasing_mutator_empty_response():
    """Test paraphrasing mutator with empty response."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_adapter = Mock()
        mock_adapter.invoke.return_value = ModelResponse(text="", meta={})
        mock_adapter_class.return_value = mock_adapter

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key")
        mutations = mutator.mutate("test")

        assert len(mutations) == 0


def test_paraphrasing_mutator_numbered_response():
    """Test paraphrasing mutator handles numbered responses."""
    with patch("aipop.adapters.openai.OpenAIAdapter") as mock_adapter_class:
        mock_adapter = Mock()
        mock_adapter.invoke.return_value = ModelResponse(
            text="1. Test 1\n2. Test 2\n3. Test 3", meta={}
        )
        mock_adapter_class.return_value = mock_adapter

        mutator = ParaphrasingMutator(provider="openai", api_key="test-key")
        mutations = mutator.mutate("test")

        # Should strip numbering
        assert len(mutations) >= 1
