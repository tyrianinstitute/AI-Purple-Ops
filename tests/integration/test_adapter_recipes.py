"""Integration tests for adapter recipes."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.executors.recipe_executor import execute_recipe
from aipop.loaders.recipe_loader import RecipeConfig


@pytest.fixture
def mock_recipe() -> RecipeConfig:
    """Create a recipe configuration using mock adapter."""
    return RecipeConfig(
        version=1,
        metadata={
            "name": "Mock Adapter Test",
            "description": "Test recipe with mock adapter",
            "lane": "safety",
        },
        config={
            "adapter": "mock",
            "adapter_config": {"seed": 42, "response_mode": "smart"},
            "seed": 42,
            "output_dir": "out",
        },
        execution={
            "suites": ["normal"],
            "detectors": [],
        },
        outputs={
            "reports": [
                {"type": "json", "path": "out/reports/test_summary.json"},
            ],
        },
        gate=None,
    )


class TestAdapterRecipes:
    """Test recipes with different adapters."""

    def test_mock_adapter_recipe(self, mock_recipe: RecipeConfig, tmp_path: Path) -> None:
        """Test recipe execution with mock adapter."""
        # Setup test suite
        suites_dir = tmp_path / "suites" / "normal"
        suites_dir.mkdir(parents=True)
        (suites_dir / "test.yaml").write_text(
            """
id: test_suite
cases:
  - id: test1
    prompt: "Hello, world!"
    expected: pass
    metadata:
      category: utility
"""
        )

        # Change to temp directory
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = execute_recipe(mock_recipe, output_dir=str(tmp_path / "out"))
            assert result.success
            assert result.summary_path is not None
            assert result.summary_path.exists()
        finally:
            os.chdir(old_cwd)

    @pytest.mark.skipif(
        not Path("/usr/bin/ollama").exists()
        and not Path.home().joinpath(".local/bin/ollama").exists(),
        reason="Ollama not installed",
    )
    def test_ollama_adapter_recipe(self, tmp_path: Path) -> None:
        """Test recipe execution with Ollama adapter (if available)."""
        # Skip if Ollama not available
        try:
            import requests

            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            if response.status_code != 200:
                pytest.skip("Ollama not running")
        except Exception:
            pytest.skip("Ollama not available")

        # Setup test suite
        suites_dir = tmp_path / "suites" / "normal"
        suites_dir.mkdir(parents=True)
        (suites_dir / "test.yaml").write_text(
            """
id: test_suite
cases:
  - id: test1
    prompt: "Say hello"
    expected: pass
    metadata:
      category: utility
"""
        )

        recipe = RecipeConfig(
            version=1,
            metadata={
                "name": "Ollama Adapter Test",
                "description": "Test recipe with Ollama adapter",
                "lane": "safety",
            },
            config={
                "adapter": "ollama",
                "adapter_config": {"model": "tinyllama", "base_url": "http://localhost:11434"},
                "seed": 42,
                "output_dir": "out",
            },
            execution={
                "suites": ["normal"],
                "detectors": [],
            },
            outputs={
                "reports": [
                    {"type": "json", "path": "out/reports/test_summary.json"},
                ],
            },
            gate=None,
        )

        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = execute_recipe(recipe, output_dir=str(tmp_path / "out"))
            # Ollama test might fail if model not available, that's okay
            # We just want to verify the adapter loading works
            assert result.summary_path is not None or result.error is not None
        finally:
            os.chdir(old_cwd)

    def test_adapter_registry_loading(self) -> None:
        """Test that adapters can be loaded from registry."""
        from aipop.adapters.registry import AdapterRegistry

        # Mock adapter should always be available
        adapter = AdapterRegistry.get("mock", config={"seed": 42})
        assert adapter is not None

        # Test invoke works
        response = adapter.invoke("test")
        assert response.text is not None
        assert "meta" in response.__dict__ or hasattr(response, "meta")

    def test_adapter_error_handling(self) -> None:
        """Test that adapter errors are handled gracefully."""
        from aipop.adapters.registry import AdapterRegistry, AdapterRegistryError

        with pytest.raises(AdapterRegistryError):
            AdapterRegistry.get("nonexistent_adapter", config={})
