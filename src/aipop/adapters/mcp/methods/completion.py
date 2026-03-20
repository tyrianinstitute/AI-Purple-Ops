"""Completion methods: completion/complete for argument suggestions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aipop.adapters.mcp.session import SessionManager

logger = logging.getLogger(__name__)


class CompletionMethods:
    """Completion API implementation."""

    def __init__(self, session_manager: SessionManager) -> None:
        """Initialize completion methods."""
        self.session_manager = session_manager

    def complete(self, ref: dict[str, Any], argument: dict[str, Any]) -> tuple[list[str], bool]:
        """Suggest completions for prompt/resource arguments.

        Returns:
            Tuple of (completions list, has_more flag)
        """
        params = {
            "ref": ref,
            "argument": argument,
        }

        response = self.session_manager.send_request("completion/complete", params)

        if response.is_error:
            raise RuntimeError("completion/complete failed")

        result = response.result or {}
        completions = result.get("completion", {}).get("values", [])
        has_more = result.get("completion", {}).get("hasMore", False)

        return completions, has_more
