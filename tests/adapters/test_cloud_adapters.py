"""Tests for cloud adapters (OpenAI, Anthropic, Bedrock)."""

from __future__ import annotations

import pytest

from aipop.adapters.anthropic import AnthropicAdapter
from aipop.adapters.bedrock import BedrockAdapter
from aipop.adapters.openai import OpenAIAdapter


class TestOpenAIAdapter:
    """Test OpenAI adapter."""

    def test_openai_adapter_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test OpenAI adapter raises error without API key."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValueError, match="API key not found"):
            OpenAIAdapter()

    def test_openai_adapter_with_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test OpenAI adapter initializes with API key."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-123")
        try:
            adapter = OpenAIAdapter()
            assert adapter.api_key == "sk-test-key-123"
            assert adapter.model == "gpt-4"
        except ImportError:
            pytest.skip("OpenAI SDK not installed")


class TestAnthropicAdapter:
    """Test Anthropic adapter."""

    def test_anthropic_adapter_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Anthropic adapter raises error without API key."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValueError, match="API key not found"):
            AnthropicAdapter()

    def test_anthropic_adapter_with_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Anthropic adapter initializes with API key."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-123")
        try:
            adapter = AnthropicAdapter()
            assert adapter.api_key == "sk-ant-test-key-123"
        except ImportError:
            pytest.skip("Anthropic SDK not installed")


class TestBedrockAdapter:
    """Test AWS Bedrock adapter."""

    def test_bedrock_adapter_initialization(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Bedrock adapter initialization."""
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        try:
            adapter = BedrockAdapter()
            assert adapter.region == "us-east-1"
        except ImportError:
            pytest.skip("boto3 not installed")
        except RuntimeError:
            # AWS credentials not configured, which is expected
            pass
