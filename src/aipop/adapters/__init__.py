"""Model adapters for test execution."""

from __future__ import annotations

from .anthropic import AnthropicAdapter
from .bedrock import BedrockAdapter
from .huggingface import HuggingFaceAdapter
from .llamacpp import LlamaCppAdapter
from .mcp_adapter import MCPAdapter
from .mock import MockAdapter
from .ollama import OllamaAdapter
from .openai import OpenAIAdapter
from .registry import AdapterRegistry

# Auto-register built-in adapters
AdapterRegistry.register("mock", MockAdapter)
AdapterRegistry.register("openai", OpenAIAdapter)
AdapterRegistry.register("anthropic", AnthropicAdapter)
AdapterRegistry.register("bedrock", BedrockAdapter)
AdapterRegistry.register("huggingface", HuggingFaceAdapter)
AdapterRegistry.register("ollama", OllamaAdapter)
AdapterRegistry.register("llamacpp", LlamaCppAdapter)
AdapterRegistry.register("mcp", MCPAdapter)

__all__ = [
    "AdapterRegistry",
    "AnthropicAdapter",
    "BedrockAdapter",
    "HuggingFaceAdapter",
    "LlamaCppAdapter",
    "MCPAdapter",
    "MockAdapter",
    "OllamaAdapter",
    "OpenAIAdapter",
]
