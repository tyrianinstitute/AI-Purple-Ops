"""Quick adapter generation for pentesting workflows.

Parses cURL commands and HTTP requests from Burp to auto-generate adapter configs.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


def parse_curl(curl_command: str) -> dict[str, Any]:
    """Parse cURL command into adapter config.

    Extracts URL, method, headers, body, and detects auth patterns.

    Args:
        curl_command: cURL command string (from browser/Burp)

    Returns:
        Dictionary with parsed connection details

    Example:
        >>> parse_curl("curl 'https://api.com/chat' -H 'Authorization: Bearer abc' -d '{\"message\":\"hi\"}'")
        {'url': 'https://api.com/chat', 'method': 'POST', 'headers': {...}, 'body': {...}}
    """
    config: dict[str, Any] = {}

    # Extract URL (handles both quoted and unquoted)
    url_match = re.search(r"curl ['\"]?([^'\"]+)['\"]?", curl_command)
    if url_match:
        config["url"] = url_match.group(1).strip()

    # Extract method (if specified, default to POST if data present)
    method_match = re.search(r"-X\s+(\w+)", curl_command)
    if method_match:
        config["method"] = method_match.group(1)
    else:
        # Default to POST if we have --data, otherwise GET
        config["method"] = "POST" if "--data" in curl_command or "-d " in curl_command else "GET"

    # Extract headers
    headers = {}
    for match in re.finditer(r"-H ['\"]([^:]+):\s*([^'\"]+)['\"]", curl_command):
        header_name = match.group(1).strip()
        header_value = match.group(2).strip()
        headers[header_name] = header_value

    config["headers"] = headers

    # Extract body (handles --data, --data-raw, -d)
    body = {}
    body_match = re.search(r"(?:--data-raw|--data|-d) ['\"]({.+?})['\"]", curl_command, re.DOTALL)
    if body_match:
        try:
            body = json.loads(body_match.group(1))
        except json.JSONDecodeError:
            # If JSON parsing fails, store as string
            body = {"raw": body_match.group(1)}

    config["body"] = body

    # Detect authentication type
    config["auth_type"] = detect_auth_type(headers)

    # Detect prompt field in body
    config["prompt_field"] = detect_prompt_field(body)

    return config


def parse_http_request(http_text: str) -> dict[str, Any]:
    """Parse raw HTTP request text (from Burp).

    Args:
        http_text: Raw HTTP request (e.g., "POST /api/chat HTTP/1.1\\nHost: api.com\\n...")

    Returns:
        Dictionary with parsed connection details
    """
    config: dict[str, Any] = {}
    lines = http_text.strip().split("\n")

    if not lines:
        return config

    # Parse request line
    request_line_match = re.match(r"(\w+)\s+([^\s]+)\s+HTTP/[\d.]+", lines[0])
    if request_line_match:
        config["method"] = request_line_match.group(1)
        path = request_line_match.group(2)
    else:
        return config

    # Parse headers
    headers = {}
    body_start = 1
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            # Empty line marks end of headers
            body_start = i + 1
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    config["headers"] = headers

    # Extract host and construct URL
    host = headers.get("Host", "")
    scheme = "https" if "443" in host or not host else "https"  # Default to https
    config["url"] = f"{scheme}://{host}{path}"

    # Parse body
    body = {}
    if body_start < len(lines):
        body_text = "\n".join(lines[body_start:])
        if body_text.strip():
            try:
                body = json.loads(body_text)
            except json.JSONDecodeError:
                body = {"raw": body_text}

    config["body"] = body
    config["auth_type"] = detect_auth_type(headers)
    config["prompt_field"] = detect_prompt_field(body)

    return config


def detect_prompt_field(body: dict[str, Any]) -> str | None:
    """Smart detection of prompt field in request body.

    Looks for common field names used for prompts.

    Args:
        body: Request body dictionary

    Returns:
        Field name or None if not found
    """
    if not body or not isinstance(body, dict):
        return None

    # Common prompt field names (in priority order)
    prompt_candidates = [
        "message",
        "prompt",
        "input",
        "query",
        "text",
        "content",
        "question",
        "user_message",
        "user_input",
    ]

    for candidate in prompt_candidates:
        if candidate in body:
            return candidate

    # Check nested structures (one level deep)
    for key, value in body.items():
        if isinstance(value, dict):
            nested_field = detect_prompt_field(value)
            if nested_field:
                return f"{key}.{nested_field}"

    return None


def detect_response_field(response_data: dict[str, Any]) -> str | None:
    """Smart detection of response text field.

    Args:
        response_data: Sample response dictionary

    Returns:
        Field path or None if not found
    """
    if not response_data or not isinstance(response_data, dict):
        return None

    # Common response field names
    response_candidates = [
        "response",
        "output",
        "message",
        "text",
        "content",
        "result",
        "answer",
        "reply",
        "completion",
    ]

    for candidate in response_candidates:
        if candidate in response_data:
            return candidate

    # Check nested structures
    for key, value in response_data.items():
        if isinstance(value, dict):
            nested_field = detect_response_field(value)
            if nested_field:
                return f"{key}.{nested_field}"

    return None


def detect_auth_type(headers: dict[str, str]) -> str:
    """Classify authentication type from headers.

    Args:
        headers: HTTP headers dictionary

    Returns:
        Auth type: 'bearer', 'api_key', 'header', or 'none'
    """
    auth_header = headers.get("Authorization", "")

    if "Bearer" in auth_header:
        return "bearer"
    elif "api" in auth_header.lower() or "key" in auth_header.lower():
        return "api_key"
    elif any(key.lower() in ["x-api-key", "api-key", "apikey"] for key in headers.keys()):
        return "header"
    else:
        return "none"


def generate_adapter_config(
    parsed_data: dict[str, Any],
    adapter_name: str,
    description: str = "Auto-generated adapter",
) -> dict[str, Any]:
    """Generate YAML-ready adapter config from parsed data.

    Args:
        parsed_data: Output from parse_curl() or parse_http_request()
        adapter_name: Name for the adapter
        description: Optional description

    Returns:
        Complete adapter config dictionary ready for YAML serialization
    """
    config = {
        "# Auto-generated adapter config": None,
        "# Edit this file if auto-detection was incorrect": None,
        "# Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "adapter": {
            "name": adapter_name,
            "type": "custom_http",
            "description": description,
        },
        "connection": {
            "base_url": parsed_data.get("url", "FIXME: Enter API endpoint URL"),
            "method": parsed_data.get("method", "POST"),
            "timeout": 60,
        },
    }

    # Add headers if present
    headers = parsed_data.get("headers", {})
    if headers:
        # Filter out auth headers (will be handled separately)
        filtered_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in ["authorization", "x-api-key", "api-key"]
        }
        if filtered_headers:
            config["connection"]["headers"] = filtered_headers

    # Auth configuration
    auth_type = parsed_data.get("auth_type", "none")
    env_var_name = f"{adapter_name.upper().replace('-', '_')}_API_KEY"

    auth_config: dict[str, Any] = {"type": auth_type}

    if auth_type == "bearer":
        auth_config["# SECURITY WARNING"] = "Do not commit secrets!"
        auth_config["# Use environment variable instead"] = f"${{{env_var_name}}}"
        auth_config["token_env_var"] = env_var_name
    elif auth_type == "api_key":
        auth_config["token_env_var"] = env_var_name
        auth_config["# api_key_param"] = "api_key"
    elif auth_type == "header":
        auth_config["token_env_var"] = env_var_name
        auth_config["# header_name"] = "X-API-Key"

    config["auth"] = auth_config

    # Request configuration
    prompt_field = parsed_data.get("prompt_field")
    request_config: dict[str, Any] = {}

    if prompt_field:
        request_config["prompt_field"] = prompt_field
    else:
        request_config["prompt_field"] = "FIXME: Enter field name for prompt (e.g., message)"

    # Extract extra fields from body (excluding prompt field)
    body = parsed_data.get("body", {})
    if isinstance(body, dict) and body:
        extra_fields = {k: v for k, v in body.items() if k != prompt_field}
        if extra_fields:
            request_config["extra_fields"] = extra_fields
        else:
            request_config["# extra_fields"] = {"model": "gpt-4", "temperature": 0.7}
    else:
        request_config["# extra_fields"] = {"model": "gpt-4", "temperature": 0.7}

    config["request"] = request_config

    # Response configuration
    response_config: dict[str, Any] = {
        "text_field": "FIXME: Enter response field path (e.g., response or data.output)",
        "# Optional fields to extract": None,
        "# model_field": "model",
        "# tokens_field": "usage.total_tokens",
        "# finish_reason_field": "finish_reason",
    }

    config["response"] = response_config

    # Add usage instructions as comments
    config["# Test the adapter"] = f"aipop adapter test {adapter_name}"
    config["# Use in scans"] = f"aipop run --suite quick_test --adapter {adapter_name}"

    return config


def save_adapter_config(config: dict[str, Any], output_path: Path) -> None:
    """Save adapter config to YAML file with nice formatting.

    Args:
        config: Adapter configuration dictionary
        output_path: Path to save YAML file
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Custom YAML formatting to preserve comments
    with output_path.open("w", encoding="utf-8") as f:
        for key, value in config.items():
            if key.startswith("#"):
                # Write comment
                if value is None:
                    f.write(f"{key}\n")
                else:
                    f.write(f"{key}: {value}\n")
            else:
                # Write structured data
                yaml.dump(
                    {key: value}, f, default_flow_style=False, sort_keys=False, allow_unicode=True
                )


def list_json_fields(data: dict[str, Any], prefix: str = "") -> list[str]:
    """List all field paths in a JSON structure.

    Args:
        data: JSON dictionary
        prefix: Current path prefix

    Returns:
        List of dot-notation field paths
    """
    fields = []

    if not isinstance(data, dict):
        return fields

    for key, value in data.items():
        current_path = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            # Recurse into nested dicts
            fields.extend(list_json_fields(value, current_path))
        else:
            # Leaf node
            fields.append(current_path)

    return fields
