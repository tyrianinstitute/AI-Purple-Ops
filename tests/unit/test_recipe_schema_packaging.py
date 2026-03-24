from __future__ import annotations

import json
from pathlib import Path

from aipop.utils.schema_resolver import load_json_schema


def test_recipe_schema_packaged_resource_matches_committed_file() -> None:
    loaded = load_json_schema("recipe.schema.json")

    # Ensure we can load via resolver (override/resource/fallback).
    assert isinstance(loaded.schema, dict)
    assert loaded.schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"

    # Drift-guard: the committed file should match what the resolver loads.
    repo_root = Path(__file__).resolve().parents[2]
    committed = repo_root / "src" / "aipop" / "schemas" / "recipe.schema.json"
    committed_obj = json.loads(committed.read_text(encoding="utf-8"))

    assert committed_obj == loaded.schema
