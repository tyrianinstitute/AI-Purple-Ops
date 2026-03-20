"""MCP capability detection and validation.

Parses server capabilities from initialize response and provides
validation for method availability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServerCapabilities:
    """Server capabilities parsed from initialize response.

    Attributes:
        tools: Server supports tools/list and tools/call
        resources: Server supports resources/list and resources/read
        prompts: Server supports prompts/list and prompts/get
        completion: Server supports completion/complete
        logging: Server supports logging/setLevel
        roots: Server supports roots/list (for stdio servers)
        sampling: Server supports sampling/suggest (advanced)
        elicitation: Server supports elicitation/request (v1.1+)
        pagination: Server supports cursor-based pagination
        streaming: Server supports SSE streaming
        raw_capabilities: Raw capabilities dict from server
    """

    tools: bool = False
    resources: bool = False
    prompts: bool = False
    completion: bool = False
    logging: bool = False
    roots: bool = False
    sampling: bool = False
    elicitation: bool = False
    pagination: bool = False
    streaming: bool = False
    raw_capabilities: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_initialize_response(cls, result: dict[str, Any]) -> ServerCapabilities:
        """Parse capabilities from initialize response.

        Args:
            result: Result object from initialize JSON-RPC response

        Returns:
            ServerCapabilities instance

        Example response:
            {
                "protocolVersion": "1.1",
                "capabilities": {
                    "tools": {"pagination": true},
                    "resources": {"templates": true},
                    "prompts": {},
                    "logging": {}
                },
                "serverInfo": {"name": "my-server", "version": "1.0.0"}
            }
        """
        raw_caps = result.get("capabilities", {})

        # Parse individual capabilities
        has_tools = "tools" in raw_caps
        has_resources = "resources" in raw_caps
        has_prompts = "prompts" in raw_caps
        has_completion = "completion" in raw_caps
        has_logging = "logging" in raw_caps
        has_roots = "roots" in raw_caps
        has_sampling = "sampling" in raw_caps
        has_elicitation = "elicitation" in raw_caps

        # Check for pagination support
        has_pagination = any(
            isinstance(cap, dict) and cap.get("pagination") for cap in raw_caps.values()
        )

        # Streaming is transport-dependent, default to False
        has_streaming = False

        caps = cls(
            tools=has_tools,
            resources=has_resources,
            prompts=has_prompts,
            completion=has_completion,
            logging=has_logging,
            roots=has_roots,
            sampling=has_sampling,
            elicitation=has_elicitation,
            pagination=has_pagination,
            streaming=has_streaming,
            raw_capabilities=raw_caps,
        )

        logger.info(f"Server capabilities: {caps.summary()}")
        return caps

    def has_capability(self, capability: str) -> bool:
        """Check if server has specific capability.

        Args:
            capability: Capability name (tools, resources, prompts, etc.)

        Returns:
            True if server supports capability, False otherwise
        """
        return getattr(self, capability.lower(), False)

    def require_capability(self, capability: str) -> None:
        """Assert that server has required capability.

        Args:
            capability: Required capability name

        Raises:
            ValueError: If capability is not available
        """
        if not self.has_capability(capability):
            from aipop.adapters.mcp.errors import MCPMethodNotAvailableError

            raise MCPMethodNotAvailableError(
                f"Server does not support '{capability}' capability",
                method=capability,
                available_capabilities=self.list_capabilities(),
            )

    def list_capabilities(self) -> list[str]:
        """List all available capabilities.

        Returns:
            List of capability names server supports
        """
        caps = []
        if self.tools:
            caps.append("tools")
        if self.resources:
            caps.append("resources")
        if self.prompts:
            caps.append("prompts")
        if self.completion:
            caps.append("completion")
        if self.logging:
            caps.append("logging")
        if self.roots:
            caps.append("roots")
        if self.sampling:
            caps.append("sampling")
        if self.elicitation:
            caps.append("elicitation")
        if self.pagination:
            caps.append("pagination")
        if self.streaming:
            caps.append("streaming")
        return caps

    def summary(self) -> str:
        """Generate human-readable capability summary.

        Returns:
            Capability summary string
        """
        caps = self.list_capabilities()
        if not caps:
            return "No capabilities"
        return ", ".join(caps)

    def supports_tools(self) -> bool:
        """Check if server supports tools API."""
        return self.tools

    def supports_resources(self) -> bool:
        """Check if server supports resources API."""
        return self.resources

    def supports_prompts(self) -> bool:
        """Check if server supports prompts API."""
        return self.prompts

    def supports_pagination(self) -> bool:
        """Check if server supports pagination."""
        return self.pagination

    def get_tools_capabilities(self) -> dict[str, Any]:
        """Get tools-specific capabilities.

        Returns:
            Tools capability dict (may include pagination, streaming, etc.)
        """
        return self.raw_capabilities.get("tools", {})

    def get_resources_capabilities(self) -> dict[str, Any]:
        """Get resources-specific capabilities.

        Returns:
            Resources capability dict (may include templates, etc.)
        """
        return self.raw_capabilities.get("resources", {})


class CapabilityValidator:
    """Validates method calls against server capabilities.

    Provides clear error messages when attempting to call methods
    the server doesn't support.
    """

    def __init__(self, capabilities: ServerCapabilities) -> None:
        """Initialize capability validator.

        Args:
            capabilities: Server capabilities from initialize
        """
        self.capabilities = capabilities

        # Map method names to required capabilities
        self.method_capability_map = {
            "tools/list": "tools",
            "tools/call": "tools",
            "resources/list": "resources",
            "resources/read": "resources",
            "resources/templates/list": "resources",
            "prompts/list": "prompts",
            "prompts/get": "prompts",
            "completion/complete": "completion",
            "logging/setLevel": "logging",
            "roots/list": "roots",
            "sampling/suggest": "sampling",
            "elicitation/request": "elicitation",
        }

    def validate_method(self, method: str) -> None:
        """Validate that method is supported by server.

        Args:
            method: JSON-RPC method name (e.g., "tools/list")

        Raises:
            MCPMethodNotAvailableError: If method not supported
        """
        # Check if method requires a capability
        required_cap = self.method_capability_map.get(method)

        if required_cap:
            if not self.capabilities.has_capability(required_cap):
                from aipop.adapters.mcp.errors import MCPMethodNotAvailableError

                raise MCPMethodNotAvailableError(
                    f"Method '{method}' not available: server lacks '{required_cap}' capability",
                    method=method,
                    available_capabilities=self.capabilities.list_capabilities(),
                )

        logger.debug(f"Method '{method}' validated against capabilities")

    def get_available_methods(self) -> list[str]:
        """Get list of methods server supports.

        Returns:
            List of method names (e.g., ["tools/list", "tools/call", ...])
        """
        methods = []
        for method, capability in self.method_capability_map.items():
            if self.capabilities.has_capability(capability):
                methods.append(method)
        return methods

    def suggest_alternatives(self, attempted_method: str) -> list[str]:
        """Suggest alternative methods when one fails.

        Args:
            attempted_method: Method that was attempted

        Returns:
            List of similar available methods
        """
        available = self.get_available_methods()

        # Simple fuzzy matching: same prefix (e.g., "tools/")
        prefix = attempted_method.split("/", maxsplit=1)[0] if "/" in attempted_method else ""
        suggestions = [m for m in available if m.startswith(prefix + "/")]

        return suggestions or available  # Return all available if no prefix match
