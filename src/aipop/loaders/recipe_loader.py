"""Recipe loader for YAML workflow templates."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import ValidationError, validate

from aipop.utils.errors import HarnessError
from aipop.utils.schema_resolver import load_json_schema


class RecipeLoadError(HarnessError):
    """Error loading or parsing recipe."""


@dataclass
class RecipeConfig:
    """Structured recipe configuration."""

    version: int
    metadata: dict[str, Any]
    config: dict[str, Any]
    execution: dict[str, Any]
    outputs: dict[str, Any] | None = None
    gate: dict[str, Any] | None = None


def resolve_variables(value: str) -> str:
    """Resolve environment variables in string.

    Supports:
    - ${VAR} - required variable
    - ${VAR:-default} - variable with default value

    Args:
        value: String with variable references

    Returns:
        Resolved string with variables substituted

    Raises:
        RecipeLoadError: If required variable is not set
    """
    # Pattern: ${VAR} or ${VAR:-default}
    pattern = r"\$\{([^}]+)\}"

    def replace_var(match: re.Match[str]) -> str:
        var_expr = match.group(1)
        if ":-" in var_expr:
            var_name, default = var_expr.split(":-", 1)
            var_name = var_name.strip()
            default = default.strip()
            return os.environ.get(var_name, default)
        else:
            var_name = var_expr.strip()
            if var_name not in os.environ:
                raise RecipeLoadError(f"Required environment variable not set: {var_name}")
            return os.environ[var_name]

    return re.sub(pattern, replace_var, value)


def resolve_config_variables(config: dict[str, Any]) -> dict[str, Any]:
    """Recursively resolve environment variables in config dictionary.

    Args:
        config: Configuration dictionary

    Returns:
        Configuration with variables resolved
    """
    resolved: dict[str, Any] = {}

    for key, value in config.items():
        if isinstance(value, str):
            # Try to resolve variables
            try:
                resolved[key] = resolve_variables(value)
            except RecipeLoadError:
                # If resolution fails, keep original value
                resolved[key] = value
        elif isinstance(value, dict):
            resolved[key] = resolve_config_variables(value)
        elif isinstance(value, list):
            resolved[key] = [
                resolve_config_variables(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            resolved[key] = value

    return resolved


def load_recipe(recipe_path: Path | str) -> RecipeConfig:  # noqa: PLR0912
    """Load and validate a recipe YAML file.

    Args:
        recipe_path: Path to recipe YAML file

    Returns:
        RecipeConfig with loaded and validated recipe

    Raises:
        RecipeLoadError: If recipe cannot be loaded or is invalid
    """
    recipe_path = Path(recipe_path)

    if not recipe_path.exists():
        raise RecipeLoadError(f"Recipe file not found: {recipe_path}")

    try:
        # Load YAML
        with recipe_path.open("r", encoding="utf-8") as f:
            recipe_data = yaml.safe_load(f)

        if not isinstance(recipe_data, dict):
            raise RecipeLoadError(
                f"Invalid recipe format: Expected dictionary, got {type(recipe_data).__name__}"
            )

        # Load and validate schema (override -> packaged resource -> repo fallback)
        try:
            loaded = load_json_schema("recipe.schema.json")
            schema = loaded.schema
            schema_source = loaded.source
        except Exception as e:
            raise RecipeLoadError(
                "Recipe schema not found or could not be loaded.\n" f"Error: {e}"
            ) from e

        try:
            validate(instance=recipe_data, schema=schema)
        except ValidationError as e:
            raise RecipeLoadError(
                f"Recipe schema validation failed: {e.message}\n"
                f"Path: {recipe_path}\n"
                f"Schema: {schema_source}"
            ) from e

        # Resolve environment variables in config section
        if "config" in recipe_data:
            recipe_data["config"] = resolve_config_variables(recipe_data["config"])

        # Resolve environment variables in outputs section
        if "outputs" in recipe_data:
            recipe_data["outputs"] = resolve_config_variables(recipe_data["outputs"])

        # Extract required fields
        version = recipe_data.get("version", 1)
        metadata = recipe_data.get("metadata", {})
        config = recipe_data.get("config", {})
        execution = recipe_data.get("execution", {})
        outputs = recipe_data.get("outputs")
        gate = recipe_data.get("gate")

        # Validate required fields
        if "name" not in metadata:
            raise RecipeLoadError("Recipe missing required field: metadata.name")
        if "lane" not in metadata:
            raise RecipeLoadError("Recipe missing required field: metadata.lane")
        if "adapter" not in config:
            raise RecipeLoadError("Recipe missing required field: config.adapter")
        if "suites" not in execution or not execution["suites"]:
            raise RecipeLoadError("Recipe missing required field: execution.suites")

        return RecipeConfig(
            version=version,
            metadata=metadata,
            config=config,
            execution=execution,
            outputs=outputs,
            gate=gate,
        )

    except yaml.YAMLError as e:
        raise RecipeLoadError(f"Error parsing YAML in {recipe_path}: {e}") from e
    except Exception as e:
        if isinstance(e, RecipeLoadError):
            raise
        raise RecipeLoadError(f"Error loading recipe {recipe_path}: {e}") from e
