"""Schema resolution and loading utilities.

Search order:
1) AIPOP_SCHEMA_DIR override (directory containing schema files)
2) Packaged resource: harness.schemas/<schema_filename>
3) Repo fallback paths (for dev/checkouts)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LoadedSchema:
    schema: dict[str, Any]
    source: str  # file path or package resource hint for error messages


def _repo_root_from_here() -> Path:
    # .../src/harness/utils/schema_resolver.py -> repo root is parents[3]
    return Path(__file__).resolve().parents[3]


def load_json_schema(schema_filename: str) -> LoadedSchema:
    """Load a JSON schema from override, package resources, or repo fallback."""
    override_dir = os.environ.get("AIPOP_SCHEMA_DIR")
    if override_dir:
        override_path = Path(override_dir) / schema_filename
        if override_path.exists():
            return LoadedSchema(
                schema=_load_json_file(override_path),
                source=str(override_path),
            )

    # Packaged resource: harness.schemas/<schema_filename>
    try:
        traversable = resources.files("aipop.schemas").joinpath(schema_filename)
        with traversable.open("rb") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("schema root must be a JSON object")
        return LoadedSchema(schema=data, source=f"package:harness.schemas/{schema_filename}")
    except (ModuleNotFoundError, FileNotFoundError):
        pass

    repo_root = _repo_root_from_here()
    candidates = [
        repo_root / "src" / "aipop" / "schemas" / schema_filename,
        # Back-compat for older docs/paths.
        repo_root / "reports" / "schemas" / schema_filename,
    ]
    for p in candidates:
        if p.exists():
            return LoadedSchema(schema=_load_json_file(p), source=str(p))

    searched = []
    if override_dir:
        searched.append(str(Path(override_dir) / schema_filename))
    searched.append(f"package:harness.schemas/{schema_filename}")
    searched.extend(str(p) for p in candidates)
    raise FileNotFoundError(f"Schema not found. Searched: {', '.join(searched)}")


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in schema file: {path}. Error: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"Schema root must be a JSON object: {path}")
    return data
