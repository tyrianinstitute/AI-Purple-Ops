"""HAR (HTTP Archive) 1.2 exporter for captured traffic.

Builds W3C HAR 1.2 compliant export files from captured requests.
Compatible with Burp Suite, Chrome DevTools, and other HAR consumers.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def _iso_timestamp(dt: datetime | str | None) -> str:
    """Convert datetime to ISO 8601 string with timezone.

    Args:
        dt: Datetime object, ISO string, or None

    Returns:
        ISO 8601 formatted string
    """
    if dt is None:
        return datetime.now(UTC).isoformat()

    if isinstance(dt, str):
        # Already a string, ensure it has timezone
        if "Z" not in dt and "+" not in dt and "-" not in dt[-6:]:
            dt += "Z"
        return dt

    # Convert datetime to UTC and format
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)

    return dt.isoformat()


def header_list(headers: dict[str, str] | None) -> list[dict[str, str]]:
    """Convert headers dict to HAR format list.

    Args:
        headers: Headers dictionary

    Returns:
        List of {name, value} dicts
    """
    if not headers:
        return []
    return [{"name": k, "value": v} for k, v in headers.items()]


def build_entry(request_data: Any) -> dict[str, Any]:
    """Build a single HAR entry from a captured request.

    Args:
        request_data: Captured request data (dict or object with attributes)

    Returns:
        HAR entry dict following W3C HAR 1.2 spec
    """

    # Handle both dict and object access
    def get_attr(obj, attr: str, default=None):
        if isinstance(obj, dict):
            return obj.get(attr, default)
        return getattr(obj, attr, default)

    # Extract fields
    method = get_attr(request_data, "method", "GET")
    url = get_attr(request_data, "url", "")
    timestamp = get_attr(request_data, "ts") or get_attr(request_data, "timestamp")
    request_headers = get_attr(request_data, "request_headers", {})
    request_body = get_attr(request_data, "request_body") or get_attr(request_data, "body")
    request_is_base64 = get_attr(request_data, "request_is_base64", False)

    status = get_attr(request_data, "status") or get_attr(request_data, "response_status", 0)
    response_headers = get_attr(request_data, "response_headers", {})
    response_body = get_attr(request_data, "response_body")
    response_is_base64 = get_attr(request_data, "response_is_base64", False)
    response_time_ms = get_attr(request_data, "response_time_ms", 0)
    server_ip = get_attr(request_data, "server_ip", "")
    session_id = get_attr(request_data, "session_id", "")

    # Build request object
    request = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": header_list(request_headers),
        "queryString": [],  # Could parse from URL
        "cookies": [],  # Could parse from Cookie header
        "headersSize": -1,  # -1 = unknown
        "bodySize": 0,
    }

    # Add request body if present
    if request_body:
        try:
            if isinstance(request_body, bytes):
                body_text = request_body.decode("utf-8", errors="replace")
                body_size = len(request_body)
            else:
                body_text = str(request_body)
                body_size = len(body_text.encode("utf-8"))

            request["bodySize"] = body_size
            request["postData"] = {
                "mimeType": (
                    request_headers.get("Content-Type", "application/octet-stream")
                    if request_headers
                    else "application/octet-stream"
                ),
                "text": body_text,
            }

            if request_is_base64:
                request["postData"]["encoding"] = "base64"

        except Exception as e:
            logger.warning(f"Error processing request body: {e}")
            request["bodySize"] = -1

    # Build response object
    response = {
        "status": int(status) if status else 0,
        "statusText": "",  # Could map from status code
        "httpVersion": "HTTP/1.1",
        "headers": header_list(response_headers),
        "cookies": [],
        "content": {
            "size": 0,
            "mimeType": "application/octet-stream",
        },
        "redirectURL": response_headers.get("Location", "") if response_headers else "",
        "headersSize": -1,
        "bodySize": 0,
    }

    # Add response body if present
    if response_body:
        try:
            if isinstance(response_body, bytes):
                body_text = response_body.decode("utf-8", errors="replace")
                body_size = len(response_body)
            else:
                body_text = str(response_body)
                body_size = len(body_text.encode("utf-8"))

            response["bodySize"] = body_size
            response["content"] = {
                "size": body_size,
                "mimeType": (
                    response_headers.get("Content-Type", "application/octet-stream")
                    if response_headers
                    else "application/octet-stream"
                ),
                "text": body_text,
            }

            if response_is_base64:
                response["content"]["encoding"] = "base64"

        except Exception as e:
            logger.warning(f"Error processing response body: {e}")
            response["bodySize"] = -1

    # Build timings object (HAR 1.2 spec)
    timings = {
        "blocked": 0,  # Time spent in queue waiting for network connection
        "dns": -1,  # DNS resolution time (-1 = not applicable)
        "connect": -1,  # Time required to create TCP connection
        "ssl": -1,  # Time required for SSL/TLS negotiation
        "send": 0,  # Time required to send HTTP request
        "wait": response_time_ms if response_time_ms else 0,  # Waiting for response from server
        "receive": 0,  # Time required to read response
    }

    # Build complete entry
    entry = {
        "startedDateTime": _iso_timestamp(timestamp),
        "time": response_time_ms if response_time_ms else 0,
        "request": request,
        "response": response,
        "cache": {},
        "timings": timings,
        "serverIPAddress": server_ip if server_ip else "",
        "connection": "",  # TCP/IP connection ID (optional)
    }

    # Add vendor extension for AI Purple Ops metadata
    if session_id:
        entry["_aipop"] = {"session_id": session_id}

    return entry


def build_har(
    requests: list[Any],
    session_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build complete HAR document from captured requests.

    Args:
        requests: List of captured request data
        session_metadata: Optional session metadata

    Returns:
        Complete HAR document following W3C HAR 1.2 spec
    """
    metadata = session_metadata or {}

    # Get version from metadata or package
    version = metadata.get("version", "1.2.2")

    har = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "AI Purple Ops",
                "version": version,
            },
            "browser": {
                "name": "AI Purple Ops CLI",
                "version": version,
            },
            "pages": [],  # Optional, we don't group by pages
            "entries": [],
        }
    }

    # Build entries
    for req in requests:
        try:
            entry = build_entry(req)
            har["log"]["entries"].append(entry)
        except Exception as e:
            logger.error(f"Error building HAR entry: {e}", exc_info=True)
            # Continue with other entries

    logger.info(f"Built HAR with {len(har['log']['entries'])} entries")

    return har


def validate_har(har: dict[str, Any]) -> list[str]:
    """Validate HAR structure (basic validation).

    Args:
        har: HAR document to validate

    Returns:
        List of validation errors (empty if valid)
    """
    errors = []

    # Check top-level structure
    if "log" not in har:
        errors.append("Missing 'log' key at root")
        return errors

    log = har["log"]

    # Check required fields
    if "version" not in log:
        errors.append("Missing 'version' in log")
    elif log["version"] not in ("1.1", "1.2"):
        errors.append(f"Invalid HAR version: {log['version']}")

    if "creator" not in log:
        errors.append("Missing 'creator' in log")
    elif not isinstance(log["creator"], dict):
        errors.append("'creator' must be an object")
    elif "name" not in log["creator"]:
        errors.append("Missing 'name' in creator")

    if "entries" not in log:
        errors.append("Missing 'entries' in log")
    elif not isinstance(log["entries"], list):
        errors.append("'entries' must be an array")

    # Validate entries
    for i, entry in enumerate(log.get("entries", [])):
        if not isinstance(entry, dict):
            errors.append(f"Entry {i} is not an object")
            continue

        # Check required entry fields
        for field in ("startedDateTime", "time", "request", "response", "cache", "timings"):
            if field not in entry:
                errors.append(f"Entry {i} missing required field: {field}")

        # Validate request/response
        if "request" in entry and not isinstance(entry["request"], dict):
            errors.append(f"Entry {i} request is not an object")

        if "response" in entry and not isinstance(entry["response"], dict):
            errors.append(f"Entry {i} response is not an object")

    return errors


def save_har(har: dict[str, Any], output_path: str) -> None:
    """Save HAR document to file.

    Args:
        har: HAR document
        output_path: Path to save HAR file

    Raises:
        ValueError: If HAR validation fails
    """
    import json

    # Validate before saving
    errors = validate_har(har)
    if errors:
        error_msg = "\n".join(errors)
        raise ValueError(f"HAR validation failed:\n{error_msg}")

    # Save with pretty formatting
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2, ensure_ascii=False)

    logger.info(f"Saved HAR to {output_path}")
