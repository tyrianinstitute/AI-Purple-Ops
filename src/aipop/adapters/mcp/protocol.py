"""JSON-RPC 2.0 protocol handler for MCP.

Implements the Model Context Protocol's JSON-RPC 2.0 message format with full
error code support and version negotiation (JSON-RPC 1.0 vs 2.0).

Specification: https://modelcontextprotocol.io/
JSON-RPC 2.0: https://www.jsonrpc.org/specification
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal


# JSON-RPC 2.0 error codes
class ErrorCode:
    """Standard JSON-RPC 2.0 and MCP-specific error codes."""

    # JSON-RPC 2.0 standard errors
    PARSE_ERROR = -32700  # Invalid JSON
    INVALID_REQUEST = -32600  # Not a valid request object
    METHOD_NOT_FOUND = -32601  # Method does not exist
    INVALID_PARAMS = -32602  # Invalid method parameters
    INTERNAL_ERROR = -32603  # Internal JSON-RPC error

    # MCP-specific errors (custom range -32000 to -32099)
    AUTH_ERROR = -32000  # Authentication/authorization failure
    INVALID_SESSION = -32001  # Session expired or not initialized
    RESOURCE_NOT_FOUND = -32002  # Requested resource doesn't exist
    METHOD_NOT_AVAILABLE = -32003  # Server lacks capability for method
    INVALID_PARAMETER_VALUE = -32004  # Parameter value is invalid
    INTERNAL_SERVER_ERROR = -32005  # Server internal error

    @classmethod
    def get_message(cls, code: int) -> str:
        """Get human-readable message for error code.

        Args:
            code: JSON-RPC error code

        Returns:
            Human-readable error message
        """
        messages = {
            cls.PARSE_ERROR: "Parse error: Invalid JSON",
            cls.INVALID_REQUEST: "Invalid request: Not a valid JSON-RPC 2.0 request",
            cls.METHOD_NOT_FOUND: "Method not found",
            cls.INVALID_PARAMS: "Invalid parameters",
            cls.INTERNAL_ERROR: "Internal JSON-RPC error",
            cls.AUTH_ERROR: "Authentication/authorization error",
            cls.INVALID_SESSION: "Invalid session: Session expired or not initialized",
            cls.RESOURCE_NOT_FOUND: "Resource not found",
            cls.METHOD_NOT_AVAILABLE: "Method not available: Server lacks capability",
            cls.INVALID_PARAMETER_VALUE: "Invalid parameter value",
            cls.INTERNAL_SERVER_ERROR: "Internal server error",
        }
        return messages.get(code, f"Unknown error (code {code})")


@dataclass
class JSONRPCError:
    """JSON-RPC 2.0 error object.

    Attributes:
        code: Numeric error code
        message: Human-readable error message
        data: Additional error information (optional)
    """

    code: int
    message: str
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"code": self.code, "message": self.message}
        if self.data is not None:
            result["data"] = self.data
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JSONRPCError:
        """Create from dictionary.

        Args:
            data: Error dictionary with code, message, optional data

        Returns:
            JSONRPCError instance
        """
        return cls(
            code=data["code"],
            message=data["message"],
            data=data.get("data"),
        )


@dataclass
class JSONRPCRequest:
    """JSON-RPC 2.0 request message.

    Attributes:
        method: Method name to invoke
        id: Request identifier (can be string, number, or null for notifications)
        params: Method parameters (dict or list, optional)
        jsonrpc: Protocol version (always "2.0")
    """

    method: str
    id: str | int | None = None
    params: dict[str, Any] | list[Any] | None = None
    jsonrpc: Literal["2.0"] = "2.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {"jsonrpc": self.jsonrpc, "method": self.method}
        if self.id is not None:
            result["id"] = self.id
        if self.params is not None:
            result["params"] = self.params
        return result

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @property
    def is_notification(self) -> bool:
        """Check if this is a notification (no response expected)."""
        return self.id is None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JSONRPCRequest:
        """Create from dictionary.

        Args:
            data: Request dictionary

        Returns:
            JSONRPCRequest instance

        Raises:
            ValueError: If required fields are missing
        """
        if "method" not in data:
            raise ValueError("Request missing 'method' field")

        return cls(
            method=data["method"],
            id=data.get("id"),
            params=data.get("params"),
            jsonrpc=data.get("jsonrpc", "2.0"),
        )


@dataclass
class JSONRPCResponse:
    """JSON-RPC 2.0 response message.

    Attributes:
        id: Request identifier matching the request
        result: Method result (mutually exclusive with error)
        error: Error object (mutually exclusive with result)
        jsonrpc: Protocol version (always "2.0")
    """

    id: str | int | None
    result: Any = None
    error: JSONRPCError | None = None
    jsonrpc: Literal["2.0"] = "2.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        response: dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            response["error"] = self.error.to_dict()
        else:
            response["result"] = self.result
        return response

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @property
    def is_error(self) -> bool:
        """Check if this response contains an error."""
        return self.error is not None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JSONRPCResponse:
        """Create from dictionary.

        Args:
            data: Response dictionary

        Returns:
            JSONRPCResponse instance
        """
        error = None
        if "error" in data:
            error = JSONRPCError.from_dict(data["error"])

        return cls(
            id=data.get("id"),
            result=data.get("result"),
            error=error,
            jsonrpc=data.get("jsonrpc", "2.0"),
        )


class ProtocolNegotiator:
    """Negotiates JSON-RPC protocol version (1.0 vs 2.0).

    MCP requires JSON-RPC 2.0, but some legacy servers may use 1.0.
    This class detects the version and provides compatibility guidance.
    """

    @staticmethod
    def detect_version(response_data: dict[str, Any]) -> Literal["1.0", "2.0", "unknown"]:
        """Detect JSON-RPC version from response.

        Args:
            response_data: Parsed JSON response

        Returns:
            "2.0" if jsonrpc field is present, "1.0" if missing, "unknown" otherwise
        """
        if "jsonrpc" in response_data:
            version = response_data["jsonrpc"]
            if version == "2.0":
                return "2.0"
            return "unknown"

        # JSON-RPC 1.0 doesn't include jsonrpc field
        # Check for other 1.0 indicators (result/error/id)
        if any(key in response_data for key in ["result", "error", "id"]):
            return "1.0"

        return "unknown"

    @staticmethod
    def is_compatible(version: str) -> bool:
        """Check if version is compatible with MCP.

        Args:
            version: Detected version string

        Returns:
            True if version 2.0, False otherwise
        """
        return version == "2.0"


def parse_json_rpc_message(raw_data: str | bytes) -> JSONRPCRequest | JSONRPCResponse:
    """Parse raw JSON-RPC message into typed object.

    Args:
        raw_data: Raw JSON string or bytes

    Returns:
        JSONRPCRequest or JSONRPCResponse object

    Raises:
        ValueError: If JSON is invalid or message format is wrong
    """
    if isinstance(raw_data, bytes):
        raw_data = raw_data.decode("utf-8")

    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object, got {type(data).__name__}")

    # Determine if it's a request or response
    if "method" in data:
        return JSONRPCRequest.from_dict(data)
    elif "result" in data or "error" in data:
        return JSONRPCResponse.from_dict(data)
    else:
        raise ValueError("Invalid JSON-RPC message: missing method/result/error")


def create_request(
    method: str,
    params: dict[str, Any] | list[Any] | None = None,
    request_id: str | int | None = None,
) -> JSONRPCRequest:
    """Create a JSON-RPC 2.0 request.

    Args:
        method: Method name to invoke
        params: Method parameters (dict or list)
        request_id: Request identifier (None for notifications)

    Returns:
        JSONRPCRequest ready to serialize
    """
    return JSONRPCRequest(method=method, id=request_id, params=params)


def create_response(
    request_id: str | int | None, result: Any = None, error: JSONRPCError | None = None
) -> JSONRPCResponse:
    """Create a JSON-RPC 2.0 response.

    Args:
        request_id: Request identifier from original request
        result: Method result (mutually exclusive with error)
        error: Error object (mutually exclusive with result)

    Returns:
        JSONRPCResponse ready to serialize
    """
    return JSONRPCResponse(id=request_id, result=result, error=error)


def create_error_response(
    request_id: str | int | None, code: int, message: str | None = None, data: Any = None
) -> JSONRPCResponse:
    """Create a JSON-RPC 2.0 error response.

    Args:
        request_id: Request identifier from original request
        code: Error code (use ErrorCode constants)
        message: Human-readable error message (auto-generated if None)
        data: Additional error information

    Returns:
        JSONRPCResponse with error
    """
    if message is None:
        message = ErrorCode.get_message(code)

    error = JSONRPCError(code=code, message=message, data=data)
    return JSONRPCResponse(id=request_id, error=error)
