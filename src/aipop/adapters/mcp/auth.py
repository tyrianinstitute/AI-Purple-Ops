"""Authentication handler for MCP connections.

Supports Bearer tokens and API keys with token refresh detection.
OAuth 2.1 with PKCE planned for v1.1.2+.

FUTURE WORK (v1.1.2+):
- OAuth 2.1 with PKCE authorization code flow
- Dynamic client registration
- Token refresh with refresh_token
- mTLS client certificate authentication
- Scope validation and audience checks
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration.

    Attributes:
        auth_type: Authentication type (bearer, api_key, none)
        token_env_var: Environment variable containing auth token
        header_name: Header name for auth token (default: Authorization)
        token_value: Direct token value (NOT RECOMMENDED, use env var)
    """

    auth_type: Literal["bearer", "api_key", "none"] = "none"
    token_env_var: str | None = None
    header_name: str = "Authorization"
    token_value: str | None = None  # Direct value (insecure, not recommended)

    def __post_init__(self) -> None:
        """Validate configuration and warn about insecure practices."""
        if self.token_value and self.auth_type != "none":
            logger.warning(
                "⚠️  Token hardcoded in config! Use environment variable instead for security.\n"
                f"   Set {self.token_env_var or 'MCP_AUTH_TOKEN'} environment variable and remove token_value."
            )


class AuthHandler:
    """Handles authentication for MCP connections.

    Features:
    - Bearer token authentication (Authorization: Bearer <token>)
    - API key authentication (custom header)
    - Environment variable loading
    - Token refresh detection (401 responses)
    - Security warnings for hardcoded tokens

    Future (v1.1.2+):
    - OAuth 2.1 with PKCE
    - mTLS certificates
    - Dynamic token refresh
    """

    def __init__(self, config: AuthConfig) -> None:
        """Initialize authentication handler.

        Args:
            config: Authentication configuration
        """
        self.config = config
        self._token: str | None = None
        self._load_token()

        logger.debug(f"Auth handler initialized: {config.auth_type}")

    def _load_token(self) -> None:
        """Load authentication token from environment or config.

        Priority:
        1. Environment variable (secure)
        2. Direct token value (insecure, warns user)
        """
        if self.config.auth_type == "none":
            return

        # Try environment variable first (secure)
        if self.config.token_env_var:
            self._token = os.getenv(self.config.token_env_var)
            if self._token:
                logger.debug(f"Loaded token from env var: {self.config.token_env_var}")
                return
            else:
                logger.warning(
                    f"Environment variable {self.config.token_env_var} not set. "
                    "Authentication will fail."
                )

        # Fall back to direct value (insecure)
        if self.config.token_value:
            self._token = self.config.token_value
            logger.debug("Using token from config (NOT RECOMMENDED)")
            return

        # No token available
        if self.config.auth_type != "none":
            logger.warning(
                "No authentication token configured. Connection may fail if server requires auth."
            )

    def get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers for HTTP requests.

        Returns:
            Dictionary of authentication headers
        """
        if self.config.auth_type == "none" or not self._token:
            return {}

        if self.config.auth_type == "bearer":
            return {self.config.header_name: f"Bearer {self._token}"}
        elif self.config.auth_type == "api_key":
            return {self.config.header_name: self._token}
        else:
            return {}

    def handle_auth_failure(self, status_code: int, response_headers: dict[str, str]) -> bool:
        """Handle authentication failure and determine if retry is possible.

        Args:
            status_code: HTTP status code (401, 403)
            response_headers: Response headers (may contain WWW-Authenticate)

        Returns:
            True if retry should be attempted (token refreshed), False otherwise
        """
        if status_code not in (401, 403):
            return False

        # Log authentication challenge if present
        www_auth = response_headers.get("WWW-Authenticate", "")
        if www_auth:
            logger.warning(f"Authentication challenge: {www_auth}")

        # For now, we don't support automatic token refresh
        # This will be added in v1.1.2 with OAuth 2.1
        logger.error(
            "Authentication failed. Check that your token is valid and not expired.\n"
            f"Token source: {'env var' if self.config.token_env_var else 'config'}\n"
            "To refresh token, update the environment variable or config and reconnect."
        )

        return False  # No retry (token refresh not yet implemented)

    def refresh_token(self) -> bool:
        """Refresh authentication token (placeholder for OAuth 2.1).

        Returns:
            True if token was refreshed, False otherwise

        Note:
            This is a placeholder for OAuth 2.1 token refresh flow.
            Implementation planned for v1.1.2.
        """
        logger.warning(
            "Token refresh not yet implemented. "
            "OAuth 2.1 with automatic refresh planned for v1.1.2."
        )
        return False

    def get_token(self) -> str | None:
        """Get current authentication token.

        Returns:
            Authentication token or None if not configured
        """
        return self._token

    def has_auth(self) -> bool:
        """Check if authentication is configured.

        Returns:
            True if auth token is available, False otherwise
        """
        return self.config.auth_type != "none" and self._token is not None


def create_auth_from_env(
    env_var: str = "MCP_AUTH_TOKEN",
    auth_type: Literal["bearer", "api_key"] = "bearer",
    header_name: str = "Authorization",
) -> AuthHandler:
    """Create auth handler from environment variable (recommended).

    Args:
        env_var: Environment variable name (default: MCP_AUTH_TOKEN)
        auth_type: Authentication type (bearer or api_key)
        header_name: Header name for auth token

    Returns:
        Configured AuthHandler

    Example:
        >>> os.environ["MCP_AUTH_TOKEN"] = "sk-..."
        >>> auth = create_auth_from_env()
        >>> headers = auth.get_auth_headers()
        >>> print(headers)
        {'Authorization': 'Bearer sk-...'}
    """
    config = AuthConfig(
        auth_type=auth_type,
        token_env_var=env_var,
        header_name=header_name,
    )
    return AuthHandler(config)


def create_no_auth() -> AuthHandler:
    """Create auth handler with no authentication (for public/local servers).

    Returns:
        AuthHandler with auth_type='none'

    Example:
        >>> auth = create_no_auth()
        >>> auth.has_auth()
        False
    """
    config = AuthConfig(auth_type="none")
    return AuthHandler(config)
