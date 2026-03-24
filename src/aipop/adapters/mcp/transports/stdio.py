"""Stdio transport for local MCP servers.

Communicates with MCP servers running as local processes via stdin/stdout pipes.
Suitable for CLI tools, local LLMs, and development servers.
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
from queue import Empty, Queue

from aipop.adapters.mcp.errors import (
    MCPProtocolError,
    MCPTimeoutError,
    MCPTransportError,
)
from aipop.adapters.mcp.protocol import JSONRPCRequest, JSONRPCResponse
from aipop.adapters.mcp.transports.base import (
    BaseTransport,
    SessionInfo,
    TransportConfig,
)

logger = logging.getLogger(__name__)


class StdioTransport(BaseTransport):
    """Stdio transport for local MCP servers.

    Spawns a local process and communicates via stdin/stdout using
    line-delimited JSON-RPC messages.

    Features:
    - Process lifecycle management (spawn, monitor, terminate)
    - Environment variable passing for auth tokens
    - Asynchronous stdout reading to prevent deadlocks
    - Graceful shutdown with cleanup
    """

    def __init__(
        self,
        command: list[str],
        config: TransportConfig | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        """Initialize stdio transport.

        Args:
            command: Command and arguments to spawn server (e.g., ["python", "server.py"])
            config: Transport configuration
            env: Environment variables for server process
            cwd: Working directory for server process
        """
        super().__init__(config)
        self.command = command
        self.env = env or {}
        self.cwd = cwd

        # Process management
        self.process: subprocess.Popen | None = None
        self.stdout_queue: Queue = Queue()
        self.stdout_thread: threading.Thread | None = None
        self.stderr_thread: threading.Thread | None = None

        logger.debug(f"Stdio transport initialized: {' '.join(command)}")

    def connect(self) -> SessionInfo:
        """Spawn server process and establish connection.

        Returns:
            SessionInfo with connection details

        Raises:
            MCPTransportError: If process spawn fails
        """
        try:
            # Spawn server process
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**subprocess.os.environ, **self.env},
                cwd=self.cwd,
                text=True,  # Use text mode for easier JSON handling
                bufsize=1,  # Line buffered
            )

            # Start background threads to read stdout/stderr
            self.stdout_thread = threading.Thread(
                target=self._read_stdout,
                daemon=True,
                name="mcp-stdio-stdout",
            )
            self.stdout_thread.start()

            self.stderr_thread = threading.Thread(
                target=self._read_stderr,
                daemon=True,
                name="mcp-stdio-stderr",
            )
            self.stderr_thread.start()

            # Give process a moment to start
            time.sleep(0.1)

            # Check if process is still running
            if self.process.poll() is not None:
                stderr_output = self.process.stderr.read() if self.process.stderr else ""
                raise MCPTransportError(
                    f"Server process terminated immediately. stderr: {stderr_output}",
                    transport_type="stdio",
                )

            session_info = SessionInfo(
                session_id=None,  # Stdio doesn't use session IDs
                transport_type="stdio",
                server_version="unknown",
                capabilities={"local": True},
                connected_at=time.time(),
            )

            self._mark_connected(session_info)
            logger.info(f"Connected to local MCP server: {' '.join(self.command)}")

            return session_info

        except subprocess.SubprocessError as e:
            raise MCPTransportError(
                f"Failed to spawn server process: {e}",
                transport_type="stdio",
            ) from e

    def send_request(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Send JSON-RPC request via stdin and receive response from stdout.

        Args:
            request: JSON-RPC request

        Returns:
            JSON-RPC response

        Raises:
            MCPTransportError: If send/receive fails
            MCPTimeoutError: If response times out
            MCPProtocolError: If response is malformed
        """
        if not self.process or not self._connected:
            raise MCPTransportError("Not connected", transport_type="stdio")

        # Send request to stdin
        try:
            request_line = request.to_json() + "\n"
            self.process.stdin.write(request_line)
            self.process.stdin.flush()
            logger.debug(f"Sent request: {request.method} (id={request.id})")
        except (BrokenPipeError, OSError) as e:
            raise MCPTransportError(
                f"Failed to write to stdin: {e}",
                transport_type="stdio",
            ) from e

        # Wait for response from stdout
        try:
            response_str = self.stdout_queue.get(timeout=self.config.timeout_read)
        except Empty as e:
            raise MCPTimeoutError(
                f"No response received within {self.config.timeout_read}s",
                timeout_type="read",
                timeout_seconds=self.config.timeout_read,
            ) from e

        # Parse response
        try:
            data = json.loads(response_str)
            return JSONRPCResponse.from_dict(data)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise MCPProtocolError(
                f"Invalid JSON-RPC response: {e}",
                raw_response=response_str[:500],
            ) from e

    def send_notification(self, request: JSONRPCRequest) -> None:
        """Send JSON-RPC notification via stdin (no response expected).

        Args:
            request: JSON-RPC notification (id must be None)
        """
        if request.id is not None:
            raise ValueError("Notifications must have id=None")

        if not self.process or not self._connected:
            raise MCPTransportError("Not connected", transport_type="stdio")

        try:
            notification_line = request.to_json() + "\n"
            self.process.stdin.write(notification_line)
            self.process.stdin.flush()
            logger.debug(f"Sent notification: {request.method}")
        except (BrokenPipeError, OSError) as e:
            logger.warning(f"Failed to send notification: {e}")

    def _read_stdout(self) -> None:
        """Background thread to read stdout lines into queue.

        Prevents deadlocks by reading stdout asynchronously.
        """
        if not self.process or not self.process.stdout:
            return

        try:
            for line in iter(self.process.stdout.readline, ""):
                if not line:
                    break
                line = line.strip()
                if line:
                    self.stdout_queue.put(line)
        except ValueError:
            # Stream closed
            pass
        finally:
            logger.debug("Stdout reader thread exiting")

    def _read_stderr(self) -> None:
        """Background thread to read stderr and log it.

        Helps with debugging server issues.
        """
        if not self.process or not self.process.stderr:
            return

        try:
            for line in iter(self.process.stderr.readline, ""):
                if not line:
                    break
                line = line.strip()
                if line:
                    logger.warning(f"Server stderr: {line}")
        except ValueError:
            # Stream closed
            pass
        finally:
            logger.debug("Stderr reader thread exiting")

    def close(self) -> None:
        """Terminate server process and clean up resources."""
        if self.process:
            # Try graceful shutdown first
            if self.process.poll() is None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    logger.warning("Server didn't terminate gracefully, killing")
                    self.process.kill()
                    self.process.wait()

            # Close streams
            if self.process.stdin:
                self.process.stdin.close()
            if self.process.stdout:
                self.process.stdout.close()
            if self.process.stderr:
                self.process.stderr.close()

        self._mark_disconnected()
        logger.debug("Stdio transport closed")

    def get_capabilities(self) -> list[str]:
        """Get transport-specific capabilities.

        Returns:
            List of capability names
        """
        return ["local", "stdio"]
