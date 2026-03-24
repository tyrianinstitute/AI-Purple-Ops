"""Finding taxonomy — human-readable titles and framework mappings."""
from __future__ import annotations
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
import yaml

TAXONOMY_PATH = Path(__file__).parent / "finding_taxonomy.yaml"

@lru_cache(maxsize=1)
def load_taxonomy() -> dict[str, Any]:
    if not TAXONOMY_PATH.exists():
        return {"findings": {}}
    with open(TAXONOMY_PATH) as f:
        return yaml.safe_load(f) or {"findings": {}}

def get_finding_title(test_id: str) -> str:
    findings = load_taxonomy().get("findings", {})
    entry = findings.get(test_id, {})
    return entry.get("title", test_id)

def get_finding_info(test_id: str) -> dict[str, Any]:
    findings = load_taxonomy().get("findings", {})
    return findings.get(test_id, {"title": test_id})
