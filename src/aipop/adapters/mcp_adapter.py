"""MCP (Model Context Protocol) Adapter - Production Grade Implementation.

Full MCP v1.1 spec compliance with three transports, authentication,
session management, and dual-mode operation (target + tool provider).

Example Usage:
    >>> from aipop.adapters.mcp_adapter import MCPAdapter
    >>> 
    >>> # From YAML config
    >>> adapter = MCPAdapter.from_config("adapters/my_server.yaml")
    >>> response = adapter.invoke("List available tools")
    >>> 
    >>> # Programmatic initialization
    >>> adapter = MCPAdapter(
    ...     url="https://api.example.com/mcp",
    ...     transport_type="http",
    ...     auth_token_env="MCP_TOKEN"
    ... )
    >>> adapter.connect()
    >>> tools = adapter.enumerate_tools()
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Literal

import yaml

from aipop.adapters.mcp.auth import AuthConfig, AuthHandler
from aipop.adapters.mcp.capabilities import ServerCapabilities
from aipop.adapters.mcp.errors import MCPError
from aipop.adapters.mcp.methods.prompts import PromptsMethods
from aipop.adapters.mcp.methods.resources import ResourcesMethods
from aipop.adapters.mcp.methods.tools import ToolsMethods
from aipop.adapters.mcp.session import SessionManager
from aipop.adapters.mcp.transports.base import TransportConfig
from aipop.adapters.mcp.transports.http import HTTPTransport
from aipop.adapters.mcp.transports.stdio import StdioTransport
from aipop.adapters.mcp.transports.websocket import WebSocketTransport
from aipop.core.models import ModelResponse

logger = logging.getLogger(__name__)


class MCPAdapter:
    """Production-grade MCP adapter implementing Adapter protocol.

    Features:
    - Three transports: HTTP (POST+SSE), stdio, WebSocket
    - Bearer/API key authentication (OAuth 2.1 in v1.1.2)
    - Full MCP spec: tools, resources, prompts, completion, logging
    - Session management with auto-reinitialize
    - Dual-mode: target adapter + tool provider bridge
    - Rate limiting, caching, retry logic

    Modes:
    - target: MCP server is attack target (default)
    - tool_provider: MCP tools available to attacker LLM
    - dual: Both modes active
    """

    def __init__(
        self,
        url: str | None = None,
        command: list[str] | None = None,
        transport_type: Literal["http", "stdio", "websocket"] = "http",
        auth_token_env: str | None = None,
        auth_type: Literal["bearer", "api_key", "none"] = "bearer",
        mode: Literal["target", "tool_provider", "dual"] = "target",
        transport_config: TransportConfig | None = None,
    ) -> None:
        """Initialize MCP adapter.

        Args:
            url: Server URL (for HTTP/WebSocket)
            command: Command to spawn server (for stdio)
            transport_type: Transport to use
            auth_token_env: Env var containing auth token
            auth_type: Authentication type
            mode: Operation mode (target, tool_provider, dual)
            transport_config: Transport configuration
        """
        self.url = url
        self.command = command
        self.transport_type = transport_type
        self.mode = mode

        # Validate inputs
        if transport_type in ("http", "websocket") and not url:
            raise ValueError(f"{transport_type} transport requires url parameter")
        if transport_type == "stdio" and not command:
            raise ValueError("stdio transport requires command parameter")

        # Initialize auth
        auth_config = AuthConfig(
            auth_type=auth_type,
            token_env_var=auth_token_env or "MCP_AUTH_TOKEN",
        )
        self.auth_handler = AuthHandler(auth_config)

        # Initialize transport
        self.transport_config = transport_config or TransportConfig()
        self.transport = self._create_transport()

        # Initialize session manager
        self.session_manager = SessionManager(self.transport)

        # Initialize method handlers
        self.tools = ToolsMethods(self.session_manager)
        self.resources = ResourcesMethods(self.session_manager)
        self.prompts = PromptsMethods(self.session_manager)

        # State
        self._connected = False
        self._capabilities: ServerCapabilities | None = None

        logger.info(f"MCP adapter initialized: {transport_type} transport, mode={mode}")

    def _create_transport(self):
        """Create transport instance based on type."""
        if self.transport_type == "http":
            return HTTPTransport(
                base_url=self.url,
                config=self.transport_config,
                auth_header=self.auth_handler.get_auth_headers(),
            )
        elif self.transport_type == "stdio":
            env = {}
            if self.auth_handler.has_auth():
                # Pass auth token to process via env var
                token_var = self.auth_handler.config.token_env_var or "MCP_AUTH_TOKEN"
                token = self.auth_handler.get_token()
                if token:
                    env[token_var] = token

            return StdioTransport(
                command=self.command,
                config=self.transport_config,
                env=env,
            )
        elif self.transport_type == "websocket":
            return WebSocketTransport(
                url=self.url,
                config=self.transport_config,
                auth_token=self.auth_handler.get_token(),
            )
        else:
            raise ValueError(f"Unsupported transport type: {self.transport_type}")

    def connect(self) -> None:
        """Connect to MCP server and perform initialize handshake."""
        if self._connected:
            logger.debug("Already connected")
            return

        try:
            # Connect transport
            self.transport.connect()

            # Perform initialize handshake
            server_info = self.session_manager.initialize()
            self._capabilities = self.session_manager.get_capabilities()

            self._connected = True

            logger.info(
                f"Connected to MCP server: {server_info.name} v{server_info.version}\n"
                f"Capabilities: {self._capabilities.summary() if self._capabilities else 'none'}"
            )

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            raise MCPError(f"Connection failed: {e}") from e

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:  # noqa: ANN401
        """Invoke MCP server with intelligent CTF-aware execution.

        This method makes MCPAdapter compatible with our standard Adapter interface
        while providing CTF-grade intelligence:
        - Auto-detects flags/secrets in responses
        - Parses hints for next steps
        - Suggests intelligent payload variations
        - Tracks conversation state

        Args:
            prompt: Input prompt (or objective for auto-exploitation)
            **kwargs: Additional parameters:
                - tool_name: Tool to call
                - tool_input: Tool parameters
                - mode: "direct" (single tool call) or "auto" (intelligent multi-turn)
                - objective: Attack objective (for auto mode)
                - max_iterations: Max attempts (for auto mode, default 5)

        Returns:
            ModelResponse with tool output, detected flags, and intelligence metadata
        """
        if not self._connected:
            self.connect()

        start_time = time.time()
        mode = kwargs.get("mode", "direct")

        try:
            if mode == "auto":
                # Intelligent auto-exploitation mode
                return self._invoke_auto(prompt, kwargs, start_time)
            else:
                # Direct mode (original behavior + intelligence)
                return self._invoke_direct(prompt, kwargs, start_time)

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.error(f"MCP invoke failed: {e}")

            return ModelResponse(
                text=f"Error: {e}",
                meta={
                    "model": "mcp-server",
                    "latency_ms": round(latency_ms, 2),
                    "cost_usd": 0.0,
                    "finish_reason": "error",
                    "error": str(e),
                },
            )

    def _invoke_direct(self, prompt: str, kwargs: dict, start_time: float) -> ModelResponse:
        """Direct tool invocation with intelligence layer.

        Args:
            prompt: Prompt text
            kwargs: Invocation parameters
            start_time: Start timestamp

        Returns:
            ModelResponse with intelligence metadata
        """
        # Lazy import to avoid circular deps
        try:
            from aipop.ctf.intelligence.mcp_response_parser import MCPResponseParser
            from aipop.ctf.intelligence.mcp_scorers import CompositeScorer

            scorer = CompositeScorer()
            parser = MCPResponseParser()
        except ImportError:
            logger.warning("CTF intelligence modules not available, using basic mode")
            scorer = None
            parser = None

        # If tool_name specified, call that tool directly
        tool_name = kwargs.get("tool_name")
        tool_input = kwargs.get("tool_input", {})

        if tool_name:
            result = self.tools.call_tool(tool_name, tool_input)
            response_text = (
                str(result.content) if not result.is_error else result.error_message or ""
            )
            is_error = result.is_error

            # Run intelligent analysis
            meta_intel = {}
            if scorer:
                score_result = scorer.score_tool_result(tool_name, result, prompt)
                meta_intel["flags_found"] = score_result.flags_found
                meta_intel["secrets_found"] = score_result.secrets_found
                meta_intel["success_score"] = score_result.score

                # Log flags immediately
                for flag in score_result.flags_found:
                    logger.info(f"🚩 FLAG DETECTED: {flag}")

            if parser:
                hints = parser.parse(result, tool_name)
                meta_intel["tools_discovered"] = hints.tools_discovered
                meta_intel["file_paths"] = hints.file_paths
                meta_intel["next_steps"] = hints.actionable_next_steps
                meta_intel["error_type"] = hints.error_type
        # Default behavior: enumerate tools and return info
        elif self._capabilities and self._capabilities.supports_tools():
            tools_list, _ = self.tools.list_tools()
            tool_names = [t.name for t in tools_list]
            response_text = f"🔍 Enumerated {len(tools_list)} MCP tools:\n\n" + "\n".join(
                f"  - {t.name}: {t.description}" for t in tools_list[:10]
            )
            is_error = False
            meta_intel = {
                "tool_count": len(tools_list),
                "tool_names": tool_names,
            }
        else:
            response_text = "No tools available on this MCP server"
            is_error = False
            meta_intel = {}

        latency_ms = (time.time() - start_time) * 1000

        return ModelResponse(
            text=response_text,
            meta={
                "model": "mcp-server",
                "latency_ms": round(latency_ms, 2),
                "cost_usd": 0.0,
                "finish_reason": "error" if is_error else "stop",
                "transport": self.transport_type,
                **meta_intel,  # Add intelligence metadata
            },
        )

    def _invoke_auto(self, objective: str, kwargs: dict, start_time: float) -> ModelResponse:
        """Auto-exploitation mode with intelligent multi-turn execution.

        Args:
            objective: Attack objective (e.g., "Extract the flag")
            kwargs: Invocation parameters
            start_time: Start timestamp

        Returns:
            ModelResponse with accumulated results
        """
        # Lazy import
        try:
            from aipop.ctf.intelligence.mcp_response_parser import MCPConversationState
            from aipop.ctf.intelligence.mcp_scorers import CompositeScorer
            from aipop.ctf.strategies.payloads.payload_engine import MCPPayloadEngine
        except ImportError:
            return ModelResponse(
                text="Auto mode requires CTF intelligence modules (not installed)",
                meta={
                    "model": "mcp-server",
                    "latency_ms": 0,
                    "cost_usd": 0.0,
                    "finish_reason": "error",
                    "error": "Missing CTF modules",
                },
            )

        scorer = CompositeScorer()
        state = MCPConversationState()
        payload_engine = MCPPayloadEngine()

        max_iterations = kwargs.get("max_iterations", 5)

        logger.info(f"🎯 Starting auto-exploitation: {objective}")

        # Strategy: enumerate → try common tools → payload fuzzing
        tools_list, _ = self.tools.list_tools()

        for i in range(max_iterations):
            logger.info(f"Auto-exploit iteration {i+1}/{max_iterations}")

            # Try each tool with smart payloads
            for tool in tools_list:
                # Get payloads for this tool
                payloads = payload_engine.get_payloads_for_tool(
                    tool.name, tool.description, objective
                )

                for payload in payloads[:3]:  # Limit to 3 payloads per tool
                    try:
                        # Adapt payload to tool schema
                        tool_input = self._adapt_payload_to_schema(tool, payload)

                        # Execute
                        result = self.tools.call_tool(tool.name, tool_input)
                        payload_engine.mark_attempted(tool.name, payload)

                        # Score and parse
                        score_result = scorer.score_tool_result(tool.name, result, objective)
                        state.update(tool.name, result, score_result)

                        # Check for success
                        if score_result.flags_found:
                            logger.info(f"🎉 SUCCESS! Found flag: {score_result.flags_found[0]}")

                            latency_ms = (time.time() - start_time) * 1000
                            return ModelResponse(
                                text=f"FLAG CAPTURED: {score_result.flags_found[0]}\n\n{state.get_summary()}",
                                meta={
                                    "model": "mcp-server",
                                    "latency_ms": round(latency_ms, 2),
                                    "cost_usd": 0.0,
                                    "finish_reason": "stop",
                                    "flags_found": state.flags_found,
                                    "tools_called": len(state.tools_called),
                                    "auto_mode": True,
                                },
                            )

                    except Exception as e:
                        logger.debug(f"Tool {tool.name} with payload failed: {e}")
                        continue

            # Check if we should pivot
            if state.should_pivot():
                logger.info("Pivoting strategy...")
                # Try untried tools
                next_tool = state.get_next_untried_tool()
                if next_tool:
                    logger.info(f"Trying discovered tool: {next_tool}")

        # Max iterations reached without flag
        latency_ms = (time.time() - start_time) * 1000

        return ModelResponse(
            text=f"Auto-exploitation completed without finding flag.\n\n{state.get_summary()}",
            meta={
                "model": "mcp-server",
                "latency_ms": round(latency_ms, 2),
                "cost_usd": 0.0,
                "finish_reason": "max_iterations",
                "flags_found": state.flags_found,
                "secrets_found": state.secrets_found,
                "tools_called": len(state.tools_called),
                "auto_mode": True,
            },
        )

    def _adapt_payload_to_schema(self, tool, payload: str) -> dict:
        """Adapt a payload string to tool's input schema.

        Args:
            tool: Tool object with schema
            payload: Payload string

        Returns:
            Dict of tool parameters
        """
        schema = tool.input_schema or {}
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Find first string-type parameter
        for param_name, param_spec in properties.items():
            if param_spec.get("type") == "string":
                return {param_name: payload}

        # Fallback: use first required param
        if required:
            return {required[0]: payload}

        # Last resort: guess common param names
        for common_name in ["query", "path", "input", "text", "command"]:
            if common_name in properties:
                return {common_name: payload}

        # Give up: return payload as-is
        return {"input": payload}

    def batch_query(self, prompts: list[str], **kwargs: Any) -> list[ModelResponse]:  # noqa: ANN401
        """Execute batch of prompts sequentially (Adapter protocol)."""
        return [self.invoke(p, **kwargs) for p in prompts]

    # MCP-specific methods for CTF exploitation

    def enumerate_tools(self) -> list:
        """Enumerate all available tools (for CTF reconnaissance)."""
        if not self._connected:
            self.connect()

        all_tools = []
        cursor = None

        while True:
            tools, cursor = self.tools.list_tools(cursor=cursor)
            all_tools.extend(tools)
            if not cursor:
                break

        return all_tools

    def enumerate_resources(self) -> list:
        """Enumerate all available resources."""
        if not self._connected:
            self.connect()

        all_resources = []
        cursor = None

        while True:
            resources, cursor = self.resources.list_resources(cursor=cursor)
            all_resources.extend(resources)
            if not cursor:
                break

        return all_resources

    def call_tool(self, name: str, input_data: dict[str, Any]) -> Any:  # noqa: ANN401
        """Call MCP tool by name (for CTF exploitation)."""
        if not self._connected:
            self.connect()

        return self.tools.call_tool(name, input_data)

    def read_resource(self, uri: str) -> dict[str, Any]:
        """Read resource by URI (for CTF exploitation)."""
        if not self._connected:
            self.connect()

        return self.resources.read_resource(uri)

    def get_capabilities(self) -> ServerCapabilities | None:
        """Get server capabilities."""
        return self._capabilities

    def close(self) -> None:
        """Close connection and clean up resources."""
        if self._connected:
            self.session_manager.shutdown()
            self._connected = False
            logger.info("MCP adapter closed")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    @classmethod
    def from_config(cls, config_path: str | Path) -> MCPAdapter:
        """Create adapter from YAML config file.

        Args:
            config_path: Path to YAML config file

        Returns:
            Configured MCPAdapter instance

        Example config (adapters/my_server.yaml):
            transport:
              type: http
              url: https://api.example.com/mcp
            auth:
              type: bearer
              token_env_var: MCP_AUTH_TOKEN
            mode: target
        """
        path = Path(config_path)

        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with path.open() as f:
            config = yaml.safe_load(f)

        transport = config.get("transport", {})
        auth = config.get("auth", {})
        mode = config.get("mode", "target")

        transport_type = transport.get("type", "http")
        url = transport.get("url")
        command = transport.get("command")

        auth_type = auth.get("type", "bearer")
        auth_token_env = auth.get("token_env_var", "MCP_AUTH_TOKEN")

        # Build transport config
        timeouts = transport.get("timeout", {})
        transport_config = TransportConfig(
            timeout_connection=timeouts.get("connection", 30),
            timeout_read=timeouts.get("read", 120),
            timeout_write=timeouts.get("write", 10),
            proxy=transport.get("proxy"),
            verify_tls=transport.get("verify_tls", True),
        )

        return cls(
            url=url,
            command=command,
            transport_type=transport_type,
            auth_token_env=auth_token_env,
            auth_type=auth_type,
            mode=mode,
            transport_config=transport_config,
        )

    @classmethod
    def from_url(
        cls,
        url: str,
        auth_token: str | None = None,
        transport_type: Literal["http", "websocket"] = "http",
    ) -> MCPAdapter:
        """Quick create adapter from URL (for testing/demos).

        Args:
            url: MCP server URL
            auth_token: Optional auth token (or set MCP_AUTH_TOKEN env var)
            transport_type: http or websocket

        Returns:
            MCPAdapter instance
        """
        if auth_token:
            os.environ["MCP_AUTH_TOKEN"] = auth_token

        return cls(
            url=url,
            transport_type=transport_type,
            auth_token_env="MCP_AUTH_TOKEN",
        )
