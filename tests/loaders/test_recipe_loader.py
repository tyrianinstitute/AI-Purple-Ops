"""Tests for recipe loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.loaders.recipe_loader import RecipeLoadError, load_recipe, resolve_variables


class TestResolveVariables:
    """Test environment variable resolution."""

    def test_resolve_simple_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test resolving a simple variable."""
        monkeypatch.setenv("TEST_VAR", "test_value")
        result = resolve_variables("${TEST_VAR}")
        assert result == "test_value"

    def test_resolve_with_default(self) -> None:
        """Test resolving variable with default value."""
        result = resolve_variables("${NONEXISTENT_VAR:-default_value}")
        assert result == "default_value"

    def test_resolve_missing_required_raises_error(self) -> None:
        """Test that missing required variable raises error."""
        with pytest.raises(RecipeLoadError, match="Required environment variable"):
            resolve_variables("${MISSING_VAR}")

    def test_resolve_multiple_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test resolving multiple variables in one string."""
        monkeypatch.setenv("VAR1", "value1")
        monkeypatch.setenv("VAR2", "value2")
        result = resolve_variables("${VAR1} and ${VAR2}")
        assert result == "value1 and value2"


class TestLoadRecipe:
    """Test recipe loading and validation."""

    def test_load_valid_recipe(self, tmp_path: Path) -> None:
        """Test loading a valid recipe."""
        recipe_file = tmp_path / "test_recipe.yaml"
        recipe_file.write_text(
            """
version: 1
metadata:
  name: "Test Recipe"
  description: "A test recipe"
  lane: safety
config:
  adapter: mock
  seed: 42
execution:
  suites:
    - normal
""",
            encoding="utf-8",
        )

        recipe = load_recipe(recipe_file)

        assert recipe.version == 1
        assert recipe.metadata["name"] == "Test Recipe"
        assert recipe.metadata["lane"] == "safety"
        assert recipe.config["adapter"] == "mock"
        assert recipe.execution["suites"] == ["normal"]

    def test_load_recipe_with_variables(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test loading recipe with environment variables."""
        monkeypatch.setenv("MODEL_ADAPTER", "openai")
        monkeypatch.setenv("SEED", "123")

        recipe_file = tmp_path / "test_recipe.yaml"
        recipe_file.write_text(
            """
version: 1
metadata:
  name: "Test Recipe"
  lane: safety
config:
  adapter: ${MODEL_ADAPTER}
  seed: ${SEED:-42}
execution:
  suites:
    - normal
""",
            encoding="utf-8",
        )

        recipe = load_recipe(recipe_file)

        assert recipe.config["adapter"] == "openai"
        assert recipe.config["seed"] == "123"

    def test_load_recipe_with_defaults(self, tmp_path: Path) -> None:
        """Test loading recipe with default values."""
        recipe_file = tmp_path / "test_recipe.yaml"
        recipe_file.write_text(
            """
version: 1
metadata:
  name: "Test Recipe"
  lane: safety
config:
  adapter: ${MODEL_ADAPTER:-mock}
  seed: ${SEED:-42}
execution:
  suites:
    - normal
""",
            encoding="utf-8",
        )

        recipe = load_recipe(recipe_file)

        assert recipe.config["adapter"] == "mock"  # Default value
        assert recipe.config["seed"] == "42"  # Default value

    def test_missing_required_field_raises_error(self, tmp_path: Path) -> None:
        """Test that missing required field raises error."""
        recipe_file = tmp_path / "test_recipe.yaml"
        recipe_file.write_text(
            """
version: 1
metadata:
  name: "Test Recipe"
  # Missing lane
config:
  adapter: mock
execution:
  suites:
    - normal
""",
            encoding="utf-8",
        )

        with pytest.raises(RecipeLoadError):
            load_recipe(recipe_file)

    def test_missing_suites_raises_error(self, tmp_path: Path) -> None:
        """Test that missing suites raises error."""
        recipe_file = tmp_path / "test_recipe.yaml"
        recipe_file.write_text(
            """
version: 1
metadata:
  name: "Test Recipe"
  lane: safety
config:
  adapter: mock
execution:
  # Missing suites
""",
            encoding="utf-8",
        )

        with pytest.raises(RecipeLoadError):
            load_recipe(recipe_file)

    def test_nonexistent_file_raises_error(self, tmp_path: Path) -> None:
        """Test that nonexistent file raises error."""
        with pytest.raises(RecipeLoadError, match="Recipe file not found"):
            load_recipe(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises_error(self, tmp_path: Path) -> None:
        """Test that invalid YAML raises error."""
        recipe_file = tmp_path / "test_recipe.yaml"
        recipe_file.write_text("invalid: yaml: content: [", encoding="utf-8")

        with pytest.raises(RecipeLoadError, match="Error parsing YAML"):
            load_recipe(recipe_file)
