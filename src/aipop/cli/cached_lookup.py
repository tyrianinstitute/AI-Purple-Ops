#!/usr/bin/env python3
"""Lightweight cache lookup - <500ms execution.

Minimal imports for fast cache-only queries. Bypasses Typer/Rich overhead.
"""

import hashlib
import json
import sys
from pathlib import Path

TOOL_VERSION = "1.2.1"


def generate_cache_key(
    method: str, prompt: str, model: str, implementation: str, params: dict
) -> str:
    """Generate cache key matching AttackCache logic with versioning."""
    # Hardcoded version to match main tool (update when version changes).
    # Keep module-level constant naming to avoid local-constant lint violations.
    version = TOOL_VERSION

    sorted_params = json.dumps(params, sort_keys=True)
    hash_input = f"{prompt}:{model}:{implementation}:{sorted_params}"
    content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    # Format: aipop:v{VERSION}:{method}:{implementation}:{hash}
    cache_key = f"aipop:v{version}:{method}:{implementation}:{content_hash}"

    return cache_key


def get_cache_path() -> Path:
    """Get DuckDB cache path."""
    # Try workspace path first
    workspace_cache = Path("out/attack_cache.duckdb")
    if workspace_cache.exists():
        return workspace_cache

    # Fall back to home directory
    home_cache = Path.home() / ".aipop" / "attack_cache.duckdb"
    if home_cache.exists():
        return home_cache

    return workspace_cache  # Default to workspace


def lookup_cached_result(
    method: str, prompt: str, model: str, implementation: str, params: dict
) -> dict | None:
    """Fast cache lookup without heavy imports."""
    try:
        import duckdb
    except ImportError:
        print("Error: duckdb not installed", file=sys.stderr)
        sys.exit(2)

    cache_key = generate_cache_key(method, prompt, model, implementation, params)
    db_path = get_cache_path()

    if not db_path.exists():
        return None

    try:
        import time

        conn = duckdb.connect(str(db_path))
        result = conn.execute(
            """
            SELECT result, expires_at, cost_usd
            FROM attack_results_cache
            WHERE cache_key = ? AND expires_at > ?
            """,
            [cache_key, time.time()],
        ).fetchone()
        conn.close()

        if result:
            result_json, _expires_at, _cost = result
            return json.loads(result_json)

        return None
    except Exception as e:
        print(f"Cache lookup error: {e}", file=sys.stderr)
        return None


def main() -> None:
    """Main entry point for fast cache lookup."""
    if len(sys.argv) < 4:
        print(
            "Usage: cached_lookup.py <method> <prompt> <model> [impl] [params_json]",
            file=sys.stderr,
        )
        sys.exit(1)

    method = sys.argv[1]
    prompt = sys.argv[2]
    model = sys.argv[3]
    implementation = sys.argv[4] if len(sys.argv) > 4 else "legacy"
    params_json = sys.argv[5] if len(sys.argv) > 5 else "{}"

    try:
        params = json.loads(params_json)
    except json.JSONDecodeError:
        print(f"Invalid params JSON: {params_json}", file=sys.stderr)
        sys.exit(1)

    result = lookup_cached_result(method, prompt, model, implementation, params)

    if result:
        # Print result as JSON
        print(json.dumps(result, indent=2))
        sys.exit(0)
    else:
        print("Cache miss", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
