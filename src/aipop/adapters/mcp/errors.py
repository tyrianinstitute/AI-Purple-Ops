"""MCP-specific error hierarchy and exception handling.

Maps JSON-RPC error codes to typed exceptions for better error handling
and provides clear error messages with troubleshooting guidance.
"""

from __future__ import annotations

from typing import Any


class MCPError(Exception):
    """Base exception for all MCP-related errors."""

    def __init__(self, message: str, code: int | None = None, data: Any = None) -> None:
        """Initialize MCP error.

        Args:
            message: Human-readable error message
            code: JSON-RPC error code (optional)
            data: Additional error information (optional)
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data

    def __str__(self) -> str:
        """String representation with code if available."""
        if self.code is not None:
            return f"[Code {self.code}] {self.message}"
        return self.message


class MCPProtocolError(MCPError):
    """Protocol-level error (malformed JSON, invalid JSON-RPC).

    Raised when:
    - JSON parsing fails
    - JSON-RPC structure is invalid
    - Required fields are missing
    - Server returns HTML instead of JSON
    """

    def __init__(self, message: str, raw_response: str | None = None) -> None:
        """Initialize protocol error.

        Args:
            message: Error description
            raw_response: Raw response text (for debugging)
        """
        super().__init__(message, code=-32700)
        self.raw_response = raw_response


class MCPTransportError(MCPError):
    """Transport-level error (connection failure, timeout).

    Raised when:
    - Cannot establish connection
    - Connection drops mid-request
    - Request/response timeout
    - Network errors (DNS, TLS, proxy)
    """

    def __init__(self, message: str, transport_type: str | None = None) -> None:
        """Initialize transport error.

        Args:
            message: Error description
            transport_type: Transport that failed (http, stdio, websocket)
        """
        super().__init__(message)
        self.transport_type = transport_type


class MCPAuthError(MCPError):
    """Authentication/authorization error.

    Raised when:
    - Missing or invalid API key/token
    - Insufficient permissions
    - OAuth flow failure
    - mTLS certificate issues

    Troubleshooting:
    - Verify token is set in environment variable
    - Check token hasn't expired
    - Ensure correct scopes/permissions
    """

    def __init__(self, message: str, auth_type: str | None = None) -> None:
        """Initialize auth error.

        Args:
            message: Error description
            auth_type: Authentication type (bearer, api_key, oauth)
        """
        super().__init__(message, code=-32000)
        self.auth_type = auth_type


class MCPSessionError(MCPError):
    """Session management error (expired, not initialized).

    Raised when:
    - Session expired due to inactivity
    - Attempting to call method before initialize
    - Session invalidated by server
    - Connection closed unexpectedly

    Recovery:
    - Session will be automatically reinitialized
    - If persistent, check server logs
    """

    def __init__(self, message: str, session_id: str | None = None) -> None:
        """Initialize session error.

        Args:
            message: Error description
            session_id: Session identifier (if available)
        """
        super().__init__(message, code=-32001)
        self.session_id = session_id


class MCPResourceNotFoundError(MCPError):
    """Requested resource doesn't exist.

    Raised when:
    - Resource URI is invalid
    - Resource was deleted
    - Incorrect resource scheme
    - Missing permissions to access resource
    """

    def __init__(self, message: str, uri: str | None = None) -> None:
        """Initialize resource not found error.

        Args:
            message: Error description
            uri: Resource URI that wasn't found
        """
        super().__init__(message, code=-32002)
        self.uri = uri


class MCPMethodNotAvailableError(MCPError):
    """Server doesn't support requested method.

    Raised when:
    - Server lacks capability for method
    - Method name is misspelled
    - Server is outdated (doesn't support new methods)

    Troubleshooting:
    - Check server capabilities via initialize response
    - Verify method name spelling
    - Update server to latest version
    """

    def __init__(
        self,
        message: str,
        method: str | None = None,
        available_capabilities: list[str] | None = None,
    ) -> None:
        """Initialize method not available error.

        Args:
            message: Error description
            method: Method name that's not available
            available_capabilities: List of capabilities server does support
        """
        super().__init__(message, code=-32003)
        self.method = method
        self.available_capabilities = available_capabilities or []


class MCPInvalidParameterError(MCPError):
    """Invalid parameter value.

    Raised when:
    - Required parameter is missing
    - Parameter type doesn't match schema
    - Parameter value out of range
    - Unknown parameter provided
    """

    def __init__(
        self, message: str, parameter_name: str | None = None, expected_type: str | None = None
    ) -> None:
        """Initialize invalid parameter error.

        Args:
            message: Error description
            parameter_name: Name of invalid parameter
            expected_type: Expected parameter type
        """
        super().__init__(message, code=-32004)
        self.parameter_name = parameter_name
        self.expected_type = expected_type


class MCPInternalServerError(MCPError):
    """Server internal error.

    Raised when:
    - Server crashes or throws exception
    - Database query fails
    - External service unavailable
    - Resource exhaustion

    Troubleshooting:
    - Check server logs
    - Verify server dependencies are running
    - Report to server maintainer if persistent
    """

    def __init__(self, message: str, server_info: dict[str, Any] | None = None) -> None:
        """Initialize internal server error.

        Args:
            message: Error description
            server_info: Server metadata (name, version) for troubleshooting
        """
        super().__init__(message, code=-32005)
        self.server_info = server_info or {}


class MCPTimeoutError(MCPTransportError):
    """Request timeout.

    Raised when:
    - Connection timeout (can't establish connection)
    - Read timeout (no response received)
    - Write timeout (can't send request)
    - Idle timeout (SSE stream inactive)

    Troubleshooting:
    - Increase timeout values in config
    - Check network connectivity
    - Verify server isn't overloaded
    - For long-running tools, use streaming
    """

    def __init__(
        self, message: str, timeout_type: str = "read", timeout_seconds: int | None = None
    ) -> None:
        """Initialize timeout error.

        Args:
            message: Error description
            timeout_type: Type of timeout (connection, read, write, idle)
            timeout_seconds: Configured timeout value
        """
        super().__init__(message)
        self.timeout_type = timeout_type
        self.timeout_seconds = timeout_seconds


class MCPRateLimitError(MCPError):
    """Rate limit exceeded.

    Raised when:
    - Too many requests in time window
    - Concurrent request limit exceeded
    - Quota exhausted

    Troubleshooting:
    - Wait for rate limit window to reset
    - Reduce request frequency
    - Upgrade server plan for higher limits
    - Enable caching to reduce duplicate requests
    """

    def __init__(
        self,
        message: str,
        retry_after: int | None = None,
        limit: int | None = None,
        remaining: int | None = None,
    ) -> None:
        """Initialize rate limit error.

        Args:
            message: Error description
            retry_after: Seconds until rate limit resets
            limit: Max requests per window
            remaining: Remaining requests in window
        """
        super().__init__(message, code=429)  # HTTP 429
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining


def map_error_code_to_exception(code: int, message: str, data: Any = None) -> MCPError:
    """Map JSON-RPC error code to appropriate exception type.

    Args:
        code: JSON-RPC error code
        message: Error message from server
        data: Additional error data

    Returns:
        Appropriate MCPError subclass instance
    """
    error_map = {
        -32700: MCPProtocolError,
        -32600: MCPProtocolError,
        -32601: MCPMethodNotAvailableError,
        -32602: MCPInvalidParameterError,
        -32603: MCPInternalServerError,
        -32000: MCPAuthError,
        -32001: MCPSessionError,
        -32002: MCPResourceNotFoundError,
        -32003: MCPMethodNotAvailableError,
        -32004: MCPInvalidParameterError,
        -32005: MCPInternalServerError,
        429: MCPRateLimitError,
    }

    error_class = error_map.get(code, MCPError)

    # Create exception with code and message
    if error_class == MCPProtocolError:
        return error_class(message, raw_response=str(data) if data else None)
    elif error_class in (
        MCPAuthError,
        MCPSessionError,
        MCPResourceNotFoundError,
        MCPMethodNotAvailableError,
        MCPInvalidParameterError,
    ):
        exc = error_class(message)
        exc.code = code
        exc.data = data
        return exc
    else:
        return error_class(message, code, data)
