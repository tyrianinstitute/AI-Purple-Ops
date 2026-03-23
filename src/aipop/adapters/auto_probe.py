"""Auto-probe adapter — discovers how to talk to a target from its URL.

The zero-friction path: `aipop scan --target http://localhost:8000/chat`
No YAML. No config. AIPOP figures out the request/response format.

Probe strategy:
1. Check for OpenAPI/Swagger spec at common paths
2. Send probe requests with common field names
3. Use whatever works

If auto-probe fails, tell the user exactly what to specify.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from aipop.adapters.custom_http import CustomHTTPAdapter
from aipop.core.models import ModelResponse


# Common prompt field names across AI APIs
PROMPT_FIELDS = ["message", "prompt", "query", "input", "text", "content", "question"]

# Common response field names across AI APIs
RESPONSE_FIELDS = ["response", "reply", "output", "text", "answer", "content", "result",
                    "choices.0.message.content", "data.response", "generated_text"]

# Common OpenAPI/docs paths
OPENAPI_PATHS = ["/openapi.json", "/docs", "/swagger.json", "/api-docs",
                 "/.well-known/openapi.json"]

PROBE_MESSAGE = "Hello, can you help me?"


def probe_target(target_url: str, timeout: int = 15) -> dict[str, Any]:
    """Probe a target URL and discover its request/response format.

    Args:
        target_url: The endpoint URL to probe
        timeout: Request timeout in seconds

    Returns:
        Config dict compatible with CustomHTTPAdapter

    Raises:
        ProbeError: If the target can't be reached or format can't be determined
    """
    results = {
        "base_url": target_url,
        "method": "POST",
        "prompt_field": None,
        "response_field": None,
        "extra_fields": {},
        "openapi": None,
        "probe_log": [],
    }

    # Step 1: Try to find OpenAPI spec
    base = _extract_base_url(target_url)
    for path in OPENAPI_PATHS:
        try:
            r = requests.get(f"{base}{path}", timeout=5)
            if r.status_code == 200 and "paths" in r.text:
                results["openapi"] = r.json()
                results["probe_log"].append(f"Found OpenAPI spec at {base}{path}")
                _extract_from_openapi(results, target_url)
                if results["prompt_field"] and results["response_field"]:
                    return results
                break
        except Exception:
            continue

    # Step 2: Probe with common field names
    for prompt_field in PROMPT_FIELDS:
        body = {prompt_field: PROBE_MESSAGE}

        try:
            r = requests.post(target_url, json=body, timeout=timeout,
                              headers={"Content-Type": "application/json"})
        except requests.ConnectionError:
            raise ProbeError(
                f"Can't connect to {target_url}. Is the target running?"
            )
        except requests.Timeout:
            raise ProbeError(
                f"Target at {target_url} timed out after {timeout}s."
            )

        if r.status_code >= 500:
            results["probe_log"].append(
                f"  {prompt_field} → {r.status_code} (server error)")
            continue

        if r.status_code == 422:
            # Validation error — wrong field name, try next
            results["probe_log"].append(
                f"  {prompt_field} → 422 (validation error, wrong field)")
            continue

        if r.status_code == 405:
            # Method not allowed — might be GET
            results["probe_log"].append(
                f"  POST → 405 (method not allowed)")
            break

        if r.status_code in (200, 201):
            results["prompt_field"] = prompt_field
            results["probe_log"].append(
                f"  {prompt_field} → {r.status_code} (accepted!)")

            # Now find the response field
            try:
                data = r.json()
                for response_field in RESPONSE_FIELDS:
                    value = _extract_nested(data, response_field)
                    if value is not None and isinstance(value, str) and len(value) > 5:
                        results["response_field"] = response_field
                        results["probe_log"].append(
                            f"  Response field: {response_field}")
                        return results

                # Didn't find a known field — list what's available
                available = _list_string_fields(data)
                if available:
                    # Pick the first string field that looks like a response
                    best = _pick_best_response_field(available, data)
                    if best:
                        results["response_field"] = best
                        results["probe_log"].append(
                            f"  Response field (guessed): {best}")
                        return results

                results["probe_log"].append(
                    f"  Got response but can't find text field. "
                    f"Available: {available}")
            except ValueError:
                results["probe_log"].append(
                    f"  Got {r.status_code} but response isn't JSON")
                continue

    if results["prompt_field"] and not results["response_field"]:
        raise ProbeError(
            f"Target accepts requests with field '{results['prompt_field']}' "
            f"but the response format is unknown.\n"
            f"Use --response-field to specify which JSON field contains the text.\n"
            f"Probe log:\n" + "\n".join(results["probe_log"])
        )

    if not results["prompt_field"]:
        raise ProbeError(
            f"Can't figure out how to talk to {target_url}.\n"
            f"Tried prompt fields: {', '.join(PROMPT_FIELDS)}\n"
            f"Use --prompt-field and --response-field to specify manually.\n"
            f"Or create an adapter YAML: cp templates/adapters/custom_http.yaml "
            f"adapters/my_target.yaml\n"
            f"Probe log:\n" + "\n".join(results["probe_log"])
        )

    return results


def build_adapter_from_probe(
    target_url: str,
    prompt_field: str | None = None,
    response_field: str | None = None,
    timeout: int = 15,
) -> CustomHTTPAdapter:
    """Build a working adapter for a target URL.

    Auto-probes if field names aren't specified. Uses explicit values if given.

    Args:
        target_url: The endpoint URL
        prompt_field: Override prompt field name (skip probe for request format)
        response_field: Override response field name (skip probe for response format)
        timeout: Request timeout

    Returns:
        Ready-to-use CustomHTTPAdapter
    """
    if prompt_field and response_field:
        # User told us everything — no probe needed
        config = {
            "connection": {
                "base_url": target_url,
                "method": "POST",
                "timeout": timeout,
                "headers": {"Content-Type": "application/json"},
            },
            "auth": {"type": "none"},
            "request": {"prompt_field": prompt_field},
            "response": {"text_field": response_field},
        }
        return CustomHTTPAdapter(config)

    # Probe the target
    probe_result = probe_target(target_url, timeout=timeout)

    # Override with explicit values if given
    if prompt_field:
        probe_result["prompt_field"] = prompt_field
    if response_field:
        probe_result["response_field"] = response_field

    config = {
        "connection": {
            "base_url": probe_result["base_url"],
            "method": probe_result["method"],
            "timeout": timeout,
            "headers": {"Content-Type": "application/json"},
        },
        "auth": {"type": "none"},
        "request": {
            "prompt_field": probe_result["prompt_field"],
            "extra_fields": probe_result.get("extra_fields", {}),
        },
        "response": {"text_field": probe_result["response_field"]},
    }
    return CustomHTTPAdapter(config)


def _extract_base_url(url: str) -> str:
    """Extract scheme + host from a full URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_nested(data: dict, path: str) -> Any:
    """Extract a value from a nested dict using dot notation."""
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _list_string_fields(data: dict, prefix: str = "") -> list[str]:
    """List all fields that contain strings in a JSON response."""
    fields = []
    if not isinstance(data, dict):
        return fields
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, str):
            fields.append(path)
        elif isinstance(value, dict):
            fields.extend(_list_string_fields(value, path))
    return fields


def _pick_best_response_field(fields: list[str], data: dict) -> str | None:
    """Pick the most likely response field from available string fields.

    Heuristic: longest string value that isn't a field like 'id', 'status', 'model'.
    """
    skip_patterns = {"id", "status", "model", "type", "name", "version",
                     "created", "object", "app", "error"}

    candidates = []
    for field in fields:
        leaf = field.split(".")[-1].lower()
        if leaf in skip_patterns:
            continue
        value = _extract_nested(data, field)
        if isinstance(value, str) and len(value) > 10:
            candidates.append((field, len(value)))

    if not candidates:
        return None

    # Return the field with the longest value — most likely the actual response
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


def _extract_from_openapi(results: dict, target_url: str) -> None:
    """Try to extract prompt/response fields from an OpenAPI spec."""
    spec = results.get("openapi", {})
    if not spec:
        return

    # Find the path that matches our target URL
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    target_path = parsed.path

    paths = spec.get("paths", {})
    if target_path not in paths:
        return

    post = paths[target_path].get("post", {})
    if not post:
        return

    # Check request body schema
    body = post.get("requestBody", {})
    schema_ref = (body.get("content", {})
                  .get("application/json", {})
                  .get("schema", {}))

    # Resolve $ref
    if "$ref" in schema_ref:
        ref_name = schema_ref["$ref"].split("/")[-1]
        schema = spec.get("components", {}).get("schemas", {}).get(ref_name, {})
    else:
        schema = schema_ref

    props = schema.get("properties", {})
    required = schema.get("required", [])

    # Find the prompt field — required string field, or common names
    for field_name in PROMPT_FIELDS:
        if field_name in props:
            results["prompt_field"] = field_name
            results["probe_log"].append(
                f"  OpenAPI: prompt field = {field_name}")
            break

    if not results["prompt_field"] and required:
        # Use the first required string field
        for req in required:
            if req in props and props[req].get("type") == "string":
                results["prompt_field"] = req
                results["probe_log"].append(
                    f"  OpenAPI: prompt field (from required) = {req}")
                break


class ProbeError(Exception):
    """Raised when auto-probe can't determine how to talk to the target."""
    pass
