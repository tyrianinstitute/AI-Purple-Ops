"""Integration tests for recipe CLI commands."""

from __future__ import annotations

from pathlib import Path

from tests.helpers.cli_runner import run_cli


def test_recipe_list(tmp_path: Path) -> None:
    """Test recipe list command."""
    # Create a recipe directory structure
    recipes_dir = tmp_path / "recipes" / "safety"
    recipes_dir.mkdir(parents=True)
    (recipes_dir / "test_recipe.yaml").write_text(
        """
version: 1
metadata:
  name: "Test Recipe"
  description: "A test recipe"
  lane: safety
config:
  adapter: mock
execution:
  suites:
    - normal
""",
        encoding="utf-8",
    )

    result = run_cli(["recipe", "list"], cwd=tmp_path)

    # Should list the recipe - check for recipe name or description
    assert result.returncode == 0
    # Recipe list shows recipe name (stem) or description
    assert "test_recipe" in result.stdout.lower() or "test recipe" in result.stdout.lower()


def test_recipe_validate_valid(project_root: Path, tmp_path: Path) -> None:
    """Test recipe validate with valid recipe."""
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
  suites:
    - normal
""",
        encoding="utf-8",
    )

    result = run_cli(["recipe", "validate", "--path", str(recipe_file)], cwd=project_root)

    assert result.returncode == 0
    assert "validation passed" in result.stdout.lower()


def test_recipe_validate_invalid(project_root: Path, tmp_path: Path) -> None:
    """Test recipe validate with invalid recipe."""
    recipe_file = tmp_path / "invalid_recipe.yaml"
    recipe_file.write_text(
        """
version: 1
metadata:
  name: "Invalid Recipe"
  # Missing lane
config:
  adapter: mock
execution:
  suites:
    - normal
""",
        encoding="utf-8",
    )

    result = run_cli(["recipe", "validate", "--path", str(recipe_file)], cwd=project_root)

    assert result.returncode == 1
    assert "validation failed" in result.stdout.lower() or "error" in result.stdout.lower()
