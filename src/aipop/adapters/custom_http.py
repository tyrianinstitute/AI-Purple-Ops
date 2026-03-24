"""Custom HTTP adapter that loads from YAML configuration.

Enables pentesters to quickly create adapters from Burp requests without writing Python code.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests

from aipop.core.models import ModelResponse


class CustomHTTPAdapter:
    """HTTP adapter driven by YAML configuration."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize adapter from YAML config.

        Args:
            config: Parsed YAML configuration dictionary
        """
        self.config = config

        # Connection settings
        connection = config.get("connection", {})
        self.base_url = connection.get("base_url", "")
        self.method = connection.get("method", "POST").upper()
        self.timeout = connection.get("timeout", 60)
        self.custom_headers = connection.get("headers", {})

        # Auth settings
        auth = config.get("auth", {})
        self.auth_type = auth.get("type", "none")
        token_env_var = auth.get("token_env_var", "")
        self.api_key = os.getenv(token_env_var) if token_env_var else None
        self.auth_header_name = auth.get("header_name", "Authorization")
        self.api_key_param = auth.get("api_key_param", "api_key")

        # Request settings
        request = config.get("request", {})
        self.prompt_field = request.get("prompt_field", "message")
        self.extra_fields = request.get("extra_fields", {})

        # Response settings
        response = config.get("response", {})
        self.response_text_field = response.get("text_field", "response")
        self.response_model_field = response.get("model_field")
        self.response_tokens_field = response.get("tokens_field")
        self.response_finish_reason_field = response.get("finish_reason_field")

        # Validate required fields
        if not self.base_url:
            raise ValueError("Missing required config: connection.base_url")
        if self.prompt_field.startswith("FIXME"):
            raise ValueError(
                f"Config needs editing: {self.prompt_field}\\n"
                f"Edit the config file and specify the correct prompt field"
            )
        if self.response_text_field.startswith("FIXME"):
            raise ValueError(
                f"Config needs editing: {self.response_text_field}\\n"
                f"Edit the config file and specify the correct response field"
            )

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:  # noqa: ANN401
        """Send prompt to custom API.

        Args:
            prompt: Input prompt
            **kwargs: Additional parameters (merged with extra_fields)

        Returns:
            ModelResponse with text and metadata
        """
        start_time = time.time()

        # Build headers
        headers = dict(self.custom_headers)
        headers["Content-Type"] = "application/json"

        # Add authentication
        if self.auth_type == "bearer" and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.auth_type == "api_key" and self.api_key:
            headers[self.auth_header_name] = self.api_key
        elif self.auth_type == "header" and self.api_key:
            headers[self.auth_header_name] = self.api_key

        # Build request body
        body = dict(self.extra_fields)

        # Set prompt field (handle nested paths like "data.message")
        if "." in self.prompt_field:
            # Nested field
            parts = self.prompt_field.split(".")
            current = body
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = prompt
        else:
            # Top-level field
            body[self.prompt_field] = prompt

        # Merge kwargs
        body.update(kwargs)

        # Send request
        try:
            response = requests.request(
                method=self.method,
                url=self.base_url,
                headers=headers,
                json=body,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            # Let error handlers in the CLI catch this
            raise

        latency_ms = (time.time() - start_time) * 1000

        # Parse response
        try:
            data = response.json()
        except ValueError as e:
            raise ValueError(
                f"Failed to parse JSON response from {self.base_url}\\n"
                f"Response: {response.text[:200]}..."
            ) from e

        # Extract text (handle nested paths like "data.response")
        response_text = self._extract_field(data, self.response_text_field)

        if response_text is None:
            raise ValueError(
                f"Response field '{self.response_text_field}' not found in response\\n"
                f"Available fields: {self._list_fields(data)}"
            )

        # Convert to string if not already
        response_text = str(response_text)

        # Extract optional metadata
        model = (
            self._extract_field(data, self.response_model_field)
            if self.response_model_field
            else "unknown"
        )
        tokens = (
            self._extract_field(data, self.response_tokens_field)
            if self.response_tokens_field
            else 0
        )
        finish_reason = (
            self._extract_field(data, self.response_finish_reason_field)
            if self.response_finish_reason_field
            else "stop"
        )

        return ModelResponse(
            text=response_text,
            meta={
                "model": str(model) if model else "unknown",
                "tokens": int(tokens) if tokens else 0,
                "latency_ms": round(latency_ms, 2),
                "cost_usd": 0.0,  # Unknown for custom APIs
                "finish_reason": str(finish_reason) if finish_reason else "stop",
            },
        )

    def _extract_field(self, data: dict[str, Any], field_path: str | None) -> Any:  # noqa: ANN401
        """Extract field from nested dict using dot notation.

        Args:
            data: Response data
            field_path: Dot-notation path (e.g., "data.response")

        Returns:
            Field value or None if not found
        """
        if not field_path:
            return None

        current = data
        for part in field_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current

    def _list_fields(self, data: dict[str, Any], prefix: str = "") -> list[str]:
        """List all available fields in response for error messages.

        Args:
            data: Response data
            prefix: Current path prefix

        Returns:
            List of field paths
        """
        fields = []

        if not isinstance(data, dict):
            return fields

        for key, value in data.items():
            current_path = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                fields.extend(self._list_fields(value, current_path))
            else:
                fields.append(current_path)

        return fields

    def batch_query(self, prompts: list[str], **kwargs: Any) -> list[ModelResponse]:  # noqa: ANN401
        """Execute batch of prompts sequentially.

        Args:
            prompts: List of prompts
            **kwargs: Additional parameters

        Returns:
            List of ModelResponse objects
        """
        return [self.invoke(prompt, **kwargs) for prompt in prompts]
