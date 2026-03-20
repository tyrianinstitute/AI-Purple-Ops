"""Tests for recipe executor."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipop.executors.recipe_executor import execute_recipe
from aipop.loaders.recipe_loader import RecipeConfig


@pytest.fixture
def sample_recipe() -> RecipeConfig:
    """Create a sample recipe configuration."""
    return RecipeConfig(
        version=1,
        metadata={
            "name": "Test Recipe",
            "description": "A test recipe",
            "lane": "safety",
        },
        config={
            "adapter": "mock",
            "seed": 42,
            "output_dir": "out",
        },
        execution={
            "suites": ["normal"],
            "detectors": [],
        },
        outputs=None,
        gate=None,
    )


class TestExecuteRecipe:
    """Test recipe execution."""

    def test_execute_basic_recipe(self, sample_recipe: RecipeConfig, tmp_path: Path) -> None:
        """Test executing a basic recipe."""
        # Ensure normal suite exists
        suites_dir = tmp_path / "suites" / "normal"
        suites_dir.mkdir(parents=True)
        (suites_dir / "basic.yaml").write_text(
            """
id: test_suite
cases:
  - id: test1
    prompt: "Hello"
    expected: pass
    metadata:
      category: utility
""",
            encoding="utf-8",
        )

        # Change to tmp_path for execution
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = execute_recipe(sample_recipe, output_dir=tmp_path / "out")

            assert result.success is True
            assert result.run_id is not None
            assert result.summary_path is not None
            assert result.summary_path.exists()
        finally:
            os.chdir(old_cwd)

    def test_execute_recipe_with_detectors(self, tmp_path: Path) -> None:
        """Test executing recipe with detector configuration."""
        # Create suite
        suites_dir = tmp_path / "suites" / "normal"
        suites_dir.mkdir(parents=True)
        (suites_dir / "basic.yaml").write_text(
            """
id: test_suite
cases:
  - id: test1
    prompt: "Hello"
    expected: pass
    metadata:
      category: utility
""",
            encoding="utf-8",
        )

        # Create policy file
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "content_policy.yaml").write_text(
            """
version: "1.0.0"
description: "Test policy"
rules:
  - id: test_rule
    category: "violence"
    severity: "high"
    description: "Test rule"
    patterns: []
    keywords: []
""",
            encoding="utf-8",
        )

        recipe = RecipeConfig(
            version=1,
            metadata={"name": "Test", "lane": "safety"},
            config={"adapter": "mock", "seed": 42},
            execution={
                "suites": ["normal"],
                "detectors": [{"harmful_content": {"threshold": 0.8}}],
            },
        )

        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = execute_recipe(recipe, output_dir=tmp_path / "out")

            assert result.success is True
        finally:
            os.chdir(old_cwd)

    def test_execute_recipe_nonexistent_suite(
        self, sample_recipe: RecipeConfig, tmp_path: Path
    ) -> None:
        """Test that nonexistent suite causes error."""
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = execute_recipe(sample_recipe, output_dir=tmp_path / "out")

            # Should fail because suite doesn't exist
            assert result.success is False
            assert result.error is not None
        finally:
            os.chdir(old_cwd)
