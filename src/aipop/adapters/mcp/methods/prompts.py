"""Prompts methods: prompts/list and prompts/get with argument validation."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aipop.adapters.mcp.session import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class Prompt:
    """Prompt definition from prompts/list."""

    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] | None = None


class PromptsMethods:
    """Prompts API implementation."""

    def __init__(self, session_manager: SessionManager) -> None:
        """Initialize prompts methods."""
        self.session_manager = session_manager

    def list_prompts(self, cursor: str | None = None) -> tuple[list[Prompt], str | None]:
        """List available prompts."""
        params = {"cursor": cursor} if cursor else None
        response = self.session_manager.send_request("prompts/list", params)

        if response.is_error:
            raise RuntimeError("prompts/list failed")

        result = response.result or {}
        prompts_data = result.get("prompts", [])
        next_cursor = result.get("nextCursor")

        prompts = [
            Prompt(
                name=p["name"],
                description=p.get("description"),
                arguments=p.get("arguments"),
            )
            for p in prompts_data
        ]

        logger.info(f"Discovered {len(prompts)} prompts")
        return prompts, next_cursor

    def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Get prompt by name with interpolated arguments."""
        params: dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments

        response = self.session_manager.send_request("prompts/get", params)

        if response.is_error:
            raise RuntimeError("prompts/get failed")

        return response.result or {}
