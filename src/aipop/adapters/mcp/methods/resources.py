"""Resources methods with URI templates (RFC 6570) and circular dependency detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aipop.adapters.mcp.session import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class Resource:
    """Resource definition from resources/list."""

    uri: str
    name: str
    description: str | None = None
    mime_type: str | None = None


@dataclass
class ResourceTemplate:
    """Resource URI template from resources/templates/list."""

    uri_template: str
    name: str
    description: str | None = None


class ResourcesMethods:
    """Resources API implementation."""

    def __init__(self, session_manager: SessionManager) -> None:
        """Initialize resources methods."""
        self.session_manager = session_manager
        self._visited_uris: set[str] = set()  # For circular dependency detection

    def list_resources(self, cursor: str | None = None) -> tuple[list[Resource], str | None]:
        """List available resources."""
        params = {"cursor": cursor} if cursor else None
        response = self.session_manager.send_request("resources/list", params)

        if response.is_error:
            raise RuntimeError(
                f"resources/list failed: {response.error.message if response.error else 'Unknown'}"
            )

        result = response.result or {}
        resources_data = result.get("resources", [])
        next_cursor = result.get("nextCursor")

        resources = [
            Resource(
                uri=r["uri"],
                name=r.get("name", r["uri"]),
                description=r.get("description"),
                mime_type=r.get("mimeType"),
            )
            for r in resources_data
        ]

        logger.info(f"Discovered {len(resources)} resources")
        return resources, next_cursor

    def read_resource(self, uri: str) -> dict[str, Any]:
        """Read resource content by URI.

        Args:
            uri: Resource URI (e.g., file:///path, http://url, custom://scheme)

        Returns:
            Resource content dict

        Raises:
            MCPResourceNotFoundError: If resource doesn't exist
            RuntimeError: If circular dependency detected
        """
        # Check for circular dependency
        if uri in self._visited_uris:
            raise RuntimeError(f"Circular dependency detected: {uri}")

        self._visited_uris.add(uri)

        try:
            params = {"uri": uri}
            response = self.session_manager.send_request("resources/read", params)

            if response.is_error:
                from aipop.adapters.mcp.errors import MCPResourceNotFoundError

                if response.error and response.error.code == -32002:
                    raise MCPResourceNotFoundError(f"Resource not found: {uri}", uri=uri)
                raise RuntimeError(
                    f"resources/read failed: {response.error.message if response.error else 'Unknown'}"
                )

            return response.result or {}
        finally:
            self._visited_uris.discard(uri)

    def list_templates(
        self, cursor: str | None = None
    ) -> tuple[list[ResourceTemplate], str | None]:
        """List resource URI templates (RFC 6570)."""
        params = {"cursor": cursor} if cursor else None
        response = self.session_manager.send_request("resources/templates/list", params)

        if response.is_error:
            raise RuntimeError("resources/templates/list failed")

        result = response.result or {}
        templates_data = result.get("resourceTemplates", [])
        next_cursor = result.get("nextCursor")

        templates = [
            ResourceTemplate(
                uri_template=t["uriTemplate"],
                name=t.get("name", t["uriTemplate"]),
                description=t.get("description"),
            )
            for t in templates_data
        ]

        logger.info(f"Discovered {len(templates)} resource templates")
        return templates, next_cursor

    def expand_template(self, template: str, variables: dict[str, str]) -> str:
        """Expand RFC 6570 URI template.

        Args:
            template: URI template (e.g., "price://{item}")
            variables: Template variables (e.g., {"item": "widget"})

        Returns:
            Expanded URI (e.g., "price://widget")
        """
        # Simple template expansion (full RFC 6570 would require external library)
        uri = template
        for key, value in variables.items():
            uri = uri.replace(f"{{{key}}}", value)
        return uri
