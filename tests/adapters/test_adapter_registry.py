"""Tests for adapter registry."""

from __future__ import annotations

import pytest

from aipop.adapters.registry import AdapterRegistry, AdapterRegistryError
from aipop.core.models import ModelResponse


class TestAdapterRegistry:
    """Test adapter registry functionality."""

    def test_list_adapters(self) -> None:
        """Test listing registered adapters."""
        adapters = AdapterRegistry.list_adapters()
        assert "mock" in adapters
        assert len(adapters) >= 1

    def test_get_mock_adapter(self) -> None:
        """Test getting mock adapter from registry."""
        adapter = AdapterRegistry.get("mock", config={"seed": 42})
        assert adapter is not None

        # Test invoke
        response = adapter.invoke("test prompt")
        assert isinstance(response, ModelResponse)
        assert response.text is not None
        assert response.meta is not None

    def test_get_nonexistent_adapter(self) -> None:
        """Test error when getting nonexistent adapter."""
        with pytest.raises(AdapterRegistryError):
            AdapterRegistry.get("nonexistent_adapter_xyz")

    def test_adapter_registration(self) -> None:
        """Test registering a custom adapter."""

        class TestAdapter:
            def invoke(self, prompt: str, **kwargs) -> ModelResponse:
                return ModelResponse(text="test", meta={})

        AdapterRegistry.register("test_adapter", TestAdapter)
        assert "test_adapter" in AdapterRegistry.list_adapters()

        adapter = AdapterRegistry.get("test_adapter")
        response = adapter.invoke("test")
        assert response.text == "test"

    def test_adapter_with_config(self) -> None:
        """Test adapter initialization with config."""
        adapter = AdapterRegistry.get("mock", config={"seed": 99, "response_mode": "echo"})
        response = adapter.invoke("hello")
        assert "hello" in response.text.lower()
